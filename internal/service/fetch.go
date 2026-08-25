package service

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
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
}

// CachedPlaintext is a decrypted object on disk ready for http.ServeContent.
type CachedPlaintext struct {
	Path    string
	Name    string
	ModTime time.Time
	Hit     bool
	ETag    string
}

// NewFetch constructs a downloader.
func NewFetch(store port.ObjectStore, enc port.Encryptor) *Fetch {
	return &Fetch{store: store, enc: enc}
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
	ctx, payload, err := unwrapForDecrypt(ctx, body, meta)
	if err != nil {
		return 0, err
	}

	if dest == "-" {
		cw := &countWriter{w: stdout}
		return cw.n, encrypt.DecryptAuto(ctx, f.enc, cw, payload)
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
	if err := encrypt.DecryptAuto(ctx, f.enc, cw, payload); err != nil {
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

// Materialize decrypts key into the plaintext cache (full object on miss).
// Within soft_ttl a hit needs no S3 call. After soft_ttl, the stale entry is
// served immediately while a background HEAD (+ Get on change) revalidates.
func (f *Fetch) Materialize(ctx context.Context, key string) (CachedPlaintext, error) {
	if f.cache == nil {
		return CachedPlaintext{}, fmt.Errorf("plaintext cache is not configured")
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

func cachedPlaintext(key string, id port.CacheID, p string, meta port.EntryMeta, hit bool) CachedPlaintext {
	mod := meta.LastModified
	return CachedPlaintext{
		Path:    p,
		Name:    path.Base(key),
		ModTime: mod,
		Hit:     hit,
		ETag:    etagForHTTP(meta, id),
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
		decCtx, payload, unwrapErr := unwrapForDecrypt(ctx, body, getMeta)
		if unwrapErr != nil {
			return unwrapErr
		}
		cw := &countWriter{w: w}
		decErr := encrypt.DecryptAuto(decCtx, f.enc, cw, payload)
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

func etagForHTTP(meta port.EntryMeta, id port.CacheID) string {
	if meta.SHA256 != "" {
		return meta.SHA256
	}
	if meta.ETag != "" {
		return meta.ETag
	}
	return string(id)
}

// unwrapForDecrypt strips S3VCTR01 when present and prefers header thumbprint.
func unwrapForDecrypt(ctx context.Context, body io.Reader, meta domain.ObjectMeta) (context.Context, io.Reader, error) {
	hdr, payload, ok, err := container.Unwrap(body)
	if err != nil {
		return ctx, nil, err
	}
	tp := meta.CryptoProThumbprint // legacy user-metadata fallback
	if ok {
		if ht := hdr.ThumbprintHex(); ht != "" {
			tp = ht
		}
	}
	return encrypt.WithCryptoProThumbprint(ctx, tp), payload, nil
}
