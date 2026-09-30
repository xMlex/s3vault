package service

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/xMlex/s3vault/internal/adapter/cache"
	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/identity"
	"github.com/xMlex/s3vault/internal/metrics"
	"github.com/xMlex/s3vault/internal/port"
)

// Fetch downloads an object and writes plaintext to dest.
type Fetch struct {
	store   port.ObjectStore
	enc     port.Encryptor
	cache   port.PlaintextCache
	bucket  string
	encFP   string
	softTTL time.Duration
	reval   singleflight.Group
	metrics *metrics.Collector
	logger  *slog.Logger
}

// CachedPlaintext is a decrypted object on disk ready for http.ServeContent.
type CachedPlaintext struct {
	Path    string
	Name    string
	ModTime time.Time
	Hit     bool
	ETag    string
	SHA256  string // plaintext hex digest when known (from S3VCTR01 / cache sidecar)
	// Ephemeral is true when Path is a per-request temp file (cache disabled).
	// Caller must Release after serving.
	Ephemeral bool
}

// Release removes an ephemeral Materialize temp file. No-op for disk-cache paths.
func (c CachedPlaintext) Release() {
	if c.Ephemeral && c.Path != "" {
		_ = os.Remove(c.Path)
	}
}

// NewFetch constructs a downloader.
func NewFetch(store port.ObjectStore, enc port.Encryptor) *Fetch {
	return &Fetch{store: store, enc: enc, logger: slog.Default()}
}

// WithLogger attaches a logger used for reads of objects that arrive without an
// S3VCTR01 container. A nil logger is ignored.
func (f *Fetch) WithLogger(l *slog.Logger) *Fetch {
	if l != nil {
		f.logger = l
	}

	return f
}

// WithCache enables plaintext disk cache (HTTP). Stdout downloads stay uncached.
func (f *Fetch) WithCache(c port.PlaintextCache, bucket, encFP string) *Fetch {
	f.cache = c
	f.bucket = bucket
	f.encFP = encFP
	return f
}

// WithSoftTTL sets how long a cache hit may be served without an S3 HEAD.
// While soft-stale, Materialize serves immediately and revalidates in the background
// (stale-while-revalidate). Zero means revalidate synchronously on every request.
func (f *Fetch) WithSoftTTL(d time.Duration) *Fetch {
	f.softTTL = d
	return f
}

// WithMetrics attaches a Prometheus collector. A nil collector is a no-op.
func (f *Fetch) WithMetrics(m *metrics.Collector) *Fetch {
	f.metrics = m
	return f
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func (f *Fetch) recordDownload(started time.Time, n int64, err error) {
	if err != nil {
		f.metrics.File(metrics.OpDownload, metrics.ResultFailed)
		return
	}
	f.metrics.File(metrics.OpDownload, metrics.ResultDownloaded)
	f.metrics.AddBytes(metrics.DirDownload, n)
	f.metrics.ObserveDownload(time.Since(started), n)
}

// Download writes key to dest. dest "-" writes to stdout.
//
// Download is a client read: the last hop on the path. It removes its own layer
// and refuses a layer it cannot, because handing the caller a file that still
// carries a container is the one unacceptable outcome.
func (f *Fetch) Download(ctx context.Context, key, dest string, stdout io.Writer) error {
	started := time.Now()
	n, err := f.download(ctx, key, dest, stdout)
	f.recordDownload(started, n, err)
	return err
}

func (f *Fetch) download(ctx context.Context, key, dest string, stdout io.Writer) (int64, error) {
	body, meta, err := f.store.Get(ctx, key)
	if err != nil {
		return 0, err
	}
	defer body.Close()

	ctx, payload, objEnc, hasContainer, err := unwrapForDecrypt(ctx, body, meta)
	if err != nil {
		return 0, err
	}

	if !hasContainer {
		f.warnLegacy(key)
	}

	if dest == "-" {
		cw := &countWriter{w: stdout}
		return cw.n, encrypt.DecryptAuto(ctx, f.enc, objEnc, cw, payload)
	}

	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, fmt.Errorf("mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".s3vault-*")
	if err != nil {
		return 0, fmt.Errorf("temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	cw := &countWriter{w: tmp}
	if err := encrypt.DecryptAuto(ctx, f.enc, objEnc, cw, payload); err != nil {
		_ = tmp.Close()
		return 0, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return 0, fmt.Errorf("fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return 0, fmt.Errorf("chmod: %w", err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return 0, fmt.Errorf("rename: %w", err)
	}
	return cw.n, nil
}

// Materialize decrypts key into a seekable plaintext file for HTTP/S3 ServeContent.
// With a disk cache: soft_ttl / SWR as configured. Without: ephemeral temp (caller Release).
func (f *Fetch) Materialize(ctx context.Context, key string) (CachedPlaintext, error) {
	if f.cache == nil {
		return f.materializeEphemeral(ctx, key)
	}
	id := cache.ID(f.bucket, key, f.encFP)

	p, cached, hit, err := f.cache.Lookup(ctx, id)
	if err != nil {
		return CachedPlaintext{}, err
	}
	if hit {
		softFresh := f.softTTL > 0 && !cached.ValidatedAt.IsZero() &&
			time.Since(cached.ValidatedAt) < f.softTTL
		out := cachedPlaintext(key, id, p, cached, true)
		if softFresh {
			f.metrics.CacheHit()
			return out, nil
		}
		if f.softTTL > 0 {
			// Stale-while-revalidate: serve now, refresh in background.
			f.metrics.CacheHit()
			f.scheduleRevalidate(key, id)
			return out, nil
		}
		// soft_ttl == 0: synchronous revalidation before serve.
		return f.materializeSync(ctx, key, id, p, cached)
	}

	f.metrics.CacheMiss()
	return f.materializeMiss(ctx, key, id)
}

func (f *Fetch) materializeEphemeral(ctx context.Context, key string) (CachedPlaintext, error) {
	remote, err := identity.ResolveRemote(ctx, f.store, key)
	if err != nil {
		return CachedPlaintext{}, err
	}
	if !remote.Exists {
		return CachedPlaintext{}, domain.ErrNotFound
	}

	tmp, err := os.CreateTemp("", "s3vault-serve-*")
	if err != nil {
		return CachedPlaintext{}, fmt.Errorf("temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	started := time.Now()
	body, getMeta, err := f.store.Get(ctx, key)
	if err != nil {
		return CachedPlaintext{}, err
	}
	defer body.Close()

	decCtx, payload, objEnc, hasContainer, err := unwrapForDecrypt(ctx, body, getMeta)
	if err != nil {
		return CachedPlaintext{}, err
	}

	if !hasContainer {
		f.warnLegacy(key)
	}
	cw := &countWriter{w: tmp}
	if err := encrypt.DecryptAuto(decCtx, f.enc, objEnc, cw, payload); err != nil {
		f.recordDownload(started, cw.n, err)
		return CachedPlaintext{}, err
	}
	if err := tmp.Sync(); err != nil {
		return CachedPlaintext{}, fmt.Errorf("fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return CachedPlaintext{}, fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return CachedPlaintext{}, fmt.Errorf("chmod: %w", err)
	}
	cleanup = false
	f.recordDownload(started, cw.n, nil)

	meta := entryMetaFromRemote(remote)
	return CachedPlaintext{
		Path:      tmpName,
		Name:      path.Base(key),
		ModTime:   meta.LastModified,
		Hit:       false,
		ETag:      etagForHTTP(meta, ""),
		SHA256:    meta.SHA256,
		Ephemeral: true,
	}, nil
}

func cachedPlaintext(key string, id port.CacheID, p string, meta port.EntryMeta, hit bool) CachedPlaintext {
	mod := meta.LastModified
	return CachedPlaintext{
		Path:    p,
		Name:    path.Base(key),
		ModTime: mod,
		Hit:     hit,
		ETag:    etagForHTTP(meta, id),
		SHA256:  meta.SHA256,
	}
}

func (f *Fetch) materializeSync(ctx context.Context, key string, id port.CacheID, p string, cached port.EntryMeta) (CachedPlaintext, error) {
	remote, err := identity.ResolveRemote(ctx, f.store, key)
	if err != nil {
		return CachedPlaintext{}, err
	}
	if !remote.Exists {
		return CachedPlaintext{}, domain.ErrNotFound
	}
	if cacheStillValid(cached, remote) {
		_ = f.cache.MarkValidated(ctx, id, entryMetaFromRemote(remote))
		f.metrics.CacheHit()
		return cachedPlaintext(key, id, p, entryMetaFromRemote(remote), true), nil
	}
	f.metrics.CacheMiss()
	return f.populateFromStore(ctx, key, id, remote)
}

func (f *Fetch) materializeMiss(ctx context.Context, key string, id port.CacheID) (CachedPlaintext, error) {
	remote, err := identity.ResolveRemote(ctx, f.store, key)
	if err != nil {
		return CachedPlaintext{}, err
	}
	if !remote.Exists {
		return CachedPlaintext{}, domain.ErrNotFound
	}
	return f.populateFromStore(ctx, key, id, remote)
}

func (f *Fetch) populateFromStore(ctx context.Context, key string, id port.CacheID, remote domain.ObjectMeta) (CachedPlaintext, error) {
	entry := entryMetaFromRemote(remote)
	started := time.Now()
	var n int64
	p, err := f.cache.Populate(ctx, id, entry, func(w io.Writer) error {
		body, getMeta, getErr := f.store.Get(ctx, key)
		if getErr != nil {
			return getErr
		}
		defer body.Close()

		decCtx, payload, objEnc, hasContainer, unwrapErr := unwrapForDecrypt(ctx, body, getMeta)
		if unwrapErr != nil {
			return unwrapErr
		}

		if !hasContainer {
			f.warnLegacy(key)
		}
		cw := &countWriter{w: w}
		decErr := encrypt.DecryptAuto(decCtx, f.enc, objEnc, cw, payload)
		n = cw.n
		return decErr
	})
	f.recordDownload(started, n, err)
	if err != nil {
		return CachedPlaintext{}, err
	}
	return cachedPlaintext(key, id, p, entry, false), nil
}

func (f *Fetch) scheduleRevalidate(key string, id port.CacheID) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_, _, _ = f.reval.Do(string(id), func() (any, error) {
			return nil, f.revalidate(ctx, key, id)
		})
	}()
}

func (f *Fetch) revalidate(ctx context.Context, key string, id port.CacheID) error {
	_, cached, hit, err := f.cache.Lookup(ctx, id)
	if err != nil {
		return err
	}
	if !hit {
		_, err := f.materializeMiss(ctx, key, id)
		return err
	}
	remote, err := identity.ResolveRemote(ctx, f.store, key)
	if err != nil {
		return err
	}
	if !remote.Exists {
		return nil
	}
	if cacheStillValid(cached, remote) {
		return f.cache.MarkValidated(ctx, id, entryMetaFromRemote(remote))
	}
	_, err = f.populateFromStore(ctx, key, id, remote)
	return err
}

func entryMetaFromRemote(remote domain.ObjectMeta) port.EntryMeta {
	return port.EntryMeta{
		ETag:         remote.ETag,
		SHA256:       remote.SHA256,
		LastModified: remote.LastModified,
		ValidatedAt:  time.Now().UTC(),
	}
}

// cacheStillValid prefers plaintext SHA-256 (content identity), then S3 ETag.
func cacheStillValid(cached port.EntryMeta, remote domain.ObjectMeta) bool {
	if cached.SHA256 != "" && remote.SHA256 != "" {
		return cached.SHA256 == remote.SHA256
	}
	if cached.ETag != "" && remote.ETag != "" {
		return cached.ETag == remote.ETag
	}
	return false
}

// etagForHTTP returns an unquoted ETag value; callers add the RFC 7232 quotes
// via strconv.Quote. Prefer plaintext SHA-256, then the backend ETag (which may
// arrive pre-quoted from S3 or from the local synthetic validator), then the id.
func etagForHTTP(meta port.EntryMeta, id port.CacheID) string {
	if meta.SHA256 != "" {
		return meta.SHA256
	}
	if e := strings.Trim(meta.ETag, `"`); e != "" {
		return e
	}
	return string(id)
}

// unwrapForDecrypt strips S3VCTR01 when present and prefers header thumbprint.
// It returns the container's payload encryption name (container.EncName) and
// whether a container was found; objEnc is "" for legacy objects.
func unwrapForDecrypt(ctx context.Context, body io.Reader, meta domain.ObjectMeta) (context.Context, io.Reader, string, bool, error) {
	hdr, payload, ok, err := container.Unwrap(body)
	if err != nil {
		return ctx, nil, "", false, err
	}

	objEnc := ""
	tp := meta.CryptoProThumbprint // legacy user-metadata fallback
	if ok {
		objEnc = container.EncName(hdr.Enc)
		if ht := hdr.ThumbprintHex(); ht != "" {
			tp = ht
		}
	}

	return encrypt.WithCryptoProThumbprint(ctx, tp), payload, objEnc, ok, nil
}

// warnLegacy flags a read of an object that arrives without an S3VCTR01
// container, where the payload encryption is not declared by a header.
//
// encryption.mode is the same source of truth the write path uses: mode=none
// writes containerless objects itself, so for such a reader the shape is its own
// normal output and is logged at debug. For an encrypting reader the shape is
// unexpected — it means the object was written by a process that does not
// encrypt, or its container was lost — and the read falls back to magic/type
// detection, which stays a warn.
func (f *Fetch) warnLegacy(key string) {
	if encryptName(f.enc) == "none" {
		f.logger.Debug("object has no S3VCTR01 container (encryption.mode=none writes none); using magic/type detection",
			slog.String("key", key))

		return
	}

	f.logger.Warn("object has no S3VCTR01 container; falling back to legacy detection",
		slog.String("key", key))
}
