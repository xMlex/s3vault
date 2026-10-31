package service

import (
	"bufio"
	"context"
	"errors"
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
	"github.com/xMlex/s3vault/internal/iocopy"
	"github.com/xMlex/s3vault/internal/metrics"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/spool"
)

// errNotSeekable reports that an object cannot be read by ranged requests: its
// payload encryption has no random access (command mode), the container is
// corrupt, or the header prefix was too short to parse. Open falls back to a
// full materialization.
var errNotSeekable = errors.New("object cannot be read by range")

// Fetch downloads an object and writes plaintext to dest.
type Fetch struct {
	store    port.ObjectStore
	enc      port.Encryptor
	fallback port.Encryptor // global profile for a user view; nil when unused
	managed  bool           // true for a per-user view with profile selection
	cache    port.PlaintextCache
	bucket   string
	encFP    string
	softTTL  time.Duration
	reval    *singleflight.Group
	spoolDir string
	eph      *ephemeralSet
	ephNS    string // target namespace, separates concurrent ephemeral entries per destination
	metrics  *metrics.Collector
	logger   *slog.Logger
}

// CachedPlaintext is a decrypted object on disk ready for http.ServeContent, or
// its metadata alone when Path is empty (see Fetch.Stat).
type CachedPlaintext struct {
	Path    string
	Size    int64 // plaintext size when known
	Name    string
	ModTime time.Time
	Hit     bool
	ETag    string
	SHA256  string // plaintext hex digest when known (from S3VCTR01 / cache sidecar)
	// Ephemeral is true when Path is a per-request temp file (cache disabled).
	// Caller must Release after serving.
	Ephemeral bool

	release func()
}

// Release removes an ephemeral Materialize temp file and drops this reader's
// reference to it. No-op for disk-cache paths and for metadata-only results.
func (c CachedPlaintext) Release() {
	if c.release != nil {
		c.release()
		return
	}
	if c.Ephemeral && c.Path != "" {
		_ = os.Remove(c.Path)
	}
}

// NewFetch constructs a downloader.
func NewFetch(store port.ObjectStore, enc port.Encryptor) *Fetch {
	return &Fetch{
		store:  store,
		enc:    enc,
		logger: slog.Default(),
		reval:  &singleflight.Group{},
		eph:    newEphemeralSet(),
	}
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

// WithProfile returns a per-request view with its own encryptor set and cache
// namespace. It shares the store, cache, spool, metrics and logger with the
// base Fetch, plus the ephemeral-file set and revalidation group; reval is a
// pointer precisely so this copy does not duplicate a mutex.
func (f *Fetch) WithProfile(primary, fallback port.Encryptor, cacheBucket, fp string) *Fetch {
	if primary == nil {
		primary = encrypt.Passthrough{}
	}

	return &Fetch{
		store:    f.store,
		enc:      primary,
		fallback: fallback,
		managed:  true,
		cache:    f.cache,
		bucket:   cacheBucket,
		encFP:    fp,
		softTTL:  f.softTTL,
		reval:    f.reval,
		spoolDir: f.spoolDir,
		eph:      f.eph,
		ephNS:    f.ephNS,
		metrics:  f.metrics,
		logger:   f.logger,
	}
}

// WithStore returns a view that reads from another object store, with the
// target namespace folded into the ephemeral-file key so two destinations
// cannot share a plaintext temp file for the same backend key.
func (f *Fetch) WithStore(store port.ObjectStore, namespace string) *Fetch {
	c := *f
	c.store = store
	c.ephNS = namespace

	return &c
}

// WithSoftTTL sets how long a cache hit may be served without an S3 HEAD.
// While soft-stale, Materialize serves immediately and revalidates in the background
// (stale-while-revalidate). Zero means revalidate synchronously on every request.
func (f *Fetch) WithSoftTTL(d time.Duration) *Fetch {
	f.softTTL = d
	return f
}

// WithSpoolDir places per-request plaintext temp files under dir. Empty keeps
// the OS temp directory, which is what the CLI and tests want; the gateway
// always sets it (server.spool_dir).
func (f *Fetch) WithSpoolDir(dir string) *Fetch {
	f.spoolDir = dir
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

	ctx, payload, objEnc, _, hasContainer, err := unwrapForDecrypt(ctx, body, meta)
	if err != nil {
		return 0, err
	}

	if !hasContainer {
		f.warnLegacy(key)
	}

	if dest == "-" {
		cw := &countWriter{w: stdout}

		return cw.n, f.decryptStream(ctx, cw, payload, objEnc)
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

	cw, bw := newBufferedCounter(tmp)
	if err := f.decryptStream(ctx, cw, payload, objEnc); err != nil {
		_ = tmp.Close()
		return 0, err
	}

	if err := bw.Flush(); err != nil {
		_ = tmp.Close()
		return 0, fmt.Errorf("flush: %w", err)
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

// newBufferedCounter writes through a buffered writer and counts plaintext
// bytes, so a chunked decrypt does not issue one write syscall per chunk.
func newBufferedCounter(w io.Writer) (*countWriter, *bufio.Writer) {
	bw := bufio.NewWriterSize(w, iocopy.BufferSize)
	return &countWriter{w: bw}, bw
}

// Stat answers a HEAD request from object metadata alone: no body is
// downloaded and nothing is decrypted. It falls back to a full materialization
// only for a legacy object that carries neither a container header nor a
// declared plaintext size, where nothing else can tell the plaintext length.
func (f *Fetch) Stat(ctx context.Context, key string) (CachedPlaintext, error) {
	if cached, ok := f.statFromCache(ctx, key); ok {
		return cached, nil
	}

	remote, err := identity.ResolveRemote(ctx, f.store, key)
	if err != nil {
		return CachedPlaintext{}, err
	}

	if !remote.Exists {
		return CachedPlaintext{}, domain.ErrNotFound
	}

	if remote.FormatVersion == "" && remote.ContentSize == 0 {
		// A containerless object carries no plaintext size. For mode=none the
		// stored bytes are the plaintext, so Head's Size is authoritative and its
		// digest (from the index or a fresh hash) is valid. Only a legacy
		// containerless object read by an encrypting profile still needs the layer
		// removed before its plaintext length is known.
		if encryptName(f.enc) == encrypt.NameNone && remote.SHA256 != "" {
			meta := entryMetaFromRemote(remote)

			return CachedPlaintext{
				Name:    path.Base(key),
				Size:    remote.Size,
				ModTime: meta.LastModified,
				ETag:    etagForHTTP(meta, ""),
				SHA256:  meta.SHA256,
			}, nil
		}

		return f.statByMaterialize(ctx, key)
	}

	meta := entryMetaFromRemote(remote)

	out := CachedPlaintext{
		Name:    path.Base(key),
		Size:    remote.ContentSize,
		ModTime: meta.LastModified,
		ETag:    etagForHTTP(meta, ""),
		SHA256:  meta.SHA256,
	}

	return out, nil
}

// statFromCache answers a HEAD from a live cache entry. It follows Materialize's
// staleness policy: inside the soft TTL the entry answers without touching the
// backend, after it the stale entry is served while a background revalidation
// refreshes identity. With soft_ttl == 0 there is no cache answer at all — the
// backend is asked every time.
func (f *Fetch) statFromCache(ctx context.Context, key string) (CachedPlaintext, bool) {
	if f.cache == nil || f.softTTL <= 0 {
		return CachedPlaintext{}, false
	}

	id := cache.ID(f.bucket, key, f.encFP)

	p, meta, hit, err := f.cache.Lookup(ctx, id)
	if err != nil || !hit {
		return CachedPlaintext{}, false
	}

	st, err := os.Stat(p)
	if err != nil {
		return CachedPlaintext{}, false
	}

	if meta.ValidatedAt.IsZero() || time.Since(meta.ValidatedAt) >= f.softTTL {
		f.scheduleRevalidate(key, id)
	}

	f.metrics.CacheHit()

	out := cachedPlaintext(key, id, p, meta, true)
	out.Size = st.Size()

	return out, true
}

func (f *Fetch) statByMaterialize(ctx context.Context, key string) (CachedPlaintext, error) {
	cached, err := f.Materialize(ctx, key)
	if err != nil {
		return CachedPlaintext{}, err
	}

	if st, statErr := os.Stat(cached.Path); statErr == nil {
		cached.Size = st.Size()
	}

	cached.Release()
	cached.Path = ""
	cached.Ephemeral = false
	cached.release = nil

	return cached, nil
}

// Open returns a seekable plaintext reader for key and the object metadata for
// response headers. With a disk cache it returns the cached file, exactly as
// Materialize does. Without one it reads through ranged backend requests, so a
// client that asks for a range fetches only the chunks covering it; objects
// whose payload cannot be read at random (command mode, legacy ciphertext) fall
// back to a full materialization.
func (f *Fetch) Open(ctx context.Context, key string) (io.ReadSeekCloser, CachedPlaintext, error) {
	if f.cache != nil {
		cached, err := f.Materialize(ctx, key)
		if err != nil {
			return nil, CachedPlaintext{}, err
		}

		fh, err := os.Open(cached.Path)
		if err != nil {
			cached.Release()
			return nil, CachedPlaintext{}, fmt.Errorf("open %s: %w", cached.Path, err)
		}

		return &releasedFile{File: fh, release: cached.Release}, cached, nil
	}

	started := time.Now()

	r, cached, err := f.openRanged(ctx, key)
	if err == nil {
		r.onClose = func(n int64, err error) { f.recordDownload(started, n, err) }

		return r, cached, nil
	}

	if !errors.Is(err, errNotSeekable) {
		return nil, CachedPlaintext{}, err
	}

	cached, err = f.materializeEphemeral(ctx, key)
	if err != nil {
		return nil, CachedPlaintext{}, err
	}

	fh, err := os.Open(cached.Path)
	if err != nil {
		cached.Release()
		return nil, CachedPlaintext{}, fmt.Errorf("open %s: %w", cached.Path, err)
	}

	return &releasedFile{File: fh, release: cached.Release}, cached, nil
}

// openRanged builds a reader over ranged backend reads, or errNotSeekable when
// the stored layer cannot be mapped to plaintext offsets.
func (f *Fetch) openRanged(ctx context.Context, key string) (*objectReader, CachedPlaintext, error) {
	body, meta, err := f.store.GetRange(ctx, key, 0, rangePrefix-1)
	if err != nil {
		return nil, CachedPlaintext{}, err
	}

	prefix, readErr := io.ReadAll(io.LimitReader(body, rangePrefix))
	_ = body.Close()

	if readErr != nil {
		return nil, CachedPlaintext{}, fmt.Errorf("read prefix %s: %w", key, readErr)
	}

	if len(prefix) >= container.HeaderSize && container.IsMagic(prefix) {
		return f.rangedContainer(ctx, key, meta, prefix)
	}

	legacyEnc := f.enc
	if f.managed {
		var encErr error

		legacyEnc, encErr = f.legacyEncryptor(prefix)
		if encErr != nil {
			return nil, CachedPlaintext{}, encErr
		}
	}

	if !encrypt.LegacyPlaintext(legacyEnc, prefix) {
		return nil, CachedPlaintext{}, errNotSeekable
	}

	// A containerless payload is served byte for byte, so the digest the store
	// reports for the stored bytes is the plaintext digest. ContentSize is the
	// declared plaintext length when the object carries it; Size is the fallback
	// for stores that report the full stored length from GetRange.
	size := meta.Size
	if meta.ContentSize > 0 {
		size = meta.ContentSize
	}

	cached := CachedPlaintext{
		Name:    path.Base(key),
		Size:    size,
		ModTime: meta.LastModified,
		ETag:    etagForHTTP(port.EntryMeta{ETag: meta.ETag, SHA256: meta.SHA256}, ""),
		SHA256:  meta.SHA256,
	}
	r := newObjectReader(ctx, size, plaintextFetcher(ctx, f.store, key, 0))

	return r, cached, nil
}

// rangedContainer maps a container object to a ranged reader by its declared
// payload encryption. A reader whose configured mode does not match the
// object's declared enc is not a layer this process can remove (DecryptAuto
// says the same), so it is reported through the full materialization path.
func (f *Fetch) rangedContainer(ctx context.Context, key string, meta domain.ObjectMeta, prefix []byte) (*objectReader, CachedPlaintext, error) {
	hdr, err := container.Parse(prefix[:container.HeaderSize])
	if err != nil {
		return nil, CachedPlaintext{}, errNotSeekable
	}

	sum := hdr.SHA256Hex()
	entry := port.EntryMeta{ETag: meta.ETag, SHA256: sum, LastModified: meta.LastModified}
	cached := CachedPlaintext{
		Name:    path.Base(key),
		Size:    hdr.PlaintextSize,
		ModTime: meta.LastModified,
		ETag:    etagForHTTP(entry, ""),
		SHA256:  sum,
	}
	payloadBase := int64(container.HeaderSize)

	enc := f.enc
	if f.managed {
		var encErr error

		enc, encErr = f.encryptorFor(container.EncName(hdr.Enc))
		if encErr != nil {
			return nil, CachedPlaintext{}, encErr
		}
	}

	switch {
	case hdr.Enc == container.EncNone && encryptName(enc) == encrypt.NameNone:
		r := newObjectReader(ctx, hdr.PlaintextSize, plaintextFetcher(ctx, f.store, key, payloadBase))

		return r, cached, nil
	case hdr.Enc == container.EncNative:
		native, ok := enc.(*encrypt.Native)
		if !ok {
			return nil, CachedPlaintext{}, errNotSeekable
		}

		dec, decErr := native.NewChunkDecryptor(prefix[container.HeaderSize:])
		if decErr != nil {
			if errors.Is(decErr, encrypt.ErrShortHeader) {
				return nil, CachedPlaintext{}, errNotSeekable
			}

			return nil, CachedPlaintext{}, fmt.Errorf("native header %s: %w", key, decErr)
		}

		fetch := &chunkFetcher{
			ctx:    ctx,
			store:  f.store,
			key:    key,
			dec:    dec,
			base:   payloadBase + int64(dec.HeaderLen()),
			chunk:  int64(dec.ChunkSize()),
			stride: int64(4 + dec.ChunkSize() + 16),
		}
		r := newObjectReader(ctx, hdr.PlaintextSize, fetch.fetch)

		return r, cached, nil
	default:
		return nil, CachedPlaintext{}, errNotSeekable
	}
}

// materializeEphemeral decrypts key into a shared temp file. Concurrent readers
// of the same cold key wait for one download instead of each fetching the whole
// object; the file is removed when the last reader releases it.
func (f *Fetch) materializeEphemeral(ctx context.Context, key string) (CachedPlaintext, error) {
	return f.eph.acquire(ctx, f.ephemeralKey(key), func(e *ephemeralFile) error {
		started := time.Now()
		err := f.fillEphemeral(ctx, key, e)
		// Counted once per actual download, not once per waiter: the metric is
		// backend egress, and a collapsed read crosses the network exactly once.
		f.recordDownload(started, e.size, err)

		return err
	})
}

// ephemeralKey namespaces a shared plaintext temp file by destination. An empty
// namespace keeps the previous key exactly, so users without a target do not
// change behaviour after the upgrade.
func (f *Fetch) ephemeralKey(key string) string {
	if f.ephNS == "" {
		return key
	}

	return f.ephNS + "\x00" + key
}

// fillEphemeral downloads key, removes its layer and writes the plaintext into
// the shared temp file described by e.
func (f *Fetch) fillEphemeral(ctx context.Context, key string, e *ephemeralFile) error {
	body, getMeta, err := f.store.Get(ctx, key)
	if err != nil {
		return err
	}
	defer body.Close()

	decCtx, payload, objEnc, hdr, hasContainer, err := unwrapForDecrypt(ctx, body, getMeta)
	if err != nil {
		return err
	}
	if !hasContainer {
		f.warnLegacy(key)
	}

	tmp, err := spool.Create(f.spoolDir, spool.GetPrefix)
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}

	tmpName := tmp.Name()

	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	cw, bw := newBufferedCounter(tmp)
	if err := f.decryptStream(decCtx, cw, payload, objEnc); err != nil {
		return err
	}

	if err := bw.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	// No fsync: the file is deleted as soon as the response is served, so it
	// only has to survive this process, and every reader sees it through the
	// page cache while it is alive.
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	committed = true

	e.path = tmpName
	e.size = cw.n
	e.name = path.Base(key)
	e.modTime = getMeta.LastModified
	e.sha256 = getMeta.SHA256

	e.etag = etagForHTTP(port.EntryMeta{ETag: getMeta.ETag, SHA256: getMeta.SHA256}, "")
	if hasContainer {
		e.sha256 = hdr.SHA256Hex()
		e.etag = etagForHTTP(port.EntryMeta{ETag: getMeta.ETag, SHA256: e.sha256}, "")
	}

	return nil
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
	return f.populateFromStore(ctx, key, id, domain.ObjectMeta{})
}

// populateFromStore fills the cache from one store.Get. The object's identity
// comes from the S3VCTR01 header of that same stream, so a cold read makes one
// request instead of a HEAD plus a 128-byte Range before it.
func (f *Fetch) populateFromStore(ctx context.Context, key string, id port.CacheID, remote domain.ObjectMeta) (CachedPlaintext, error) {
	entry := entryMetaFromRemote(remote)
	started := time.Now()

	var (
		hdr          container.Header
		getMeta      domain.ObjectMeta
		hasContainer bool
		produced     int64
	)

	p, err := f.cache.Populate(ctx, id, entry, func(w io.Writer) error {
		body, meta, getErr := f.store.Get(ctx, key)
		if getErr != nil {
			return getErr
		}
		defer body.Close()

		decCtx, payload, objEnc, h, ok, unwrapErr := unwrapForDecrypt(ctx, body, meta)
		if unwrapErr != nil {
			return unwrapErr
		}

		hdr, hasContainer, getMeta = h, ok, meta
		if !hasContainer {
			f.warnLegacy(key)
		}

		cw, bw := newBufferedCounter(w)
		if decErr := f.decryptStream(decCtx, cw, payload, objEnc); decErr != nil {
			return decErr
		}

		if flushErr := bw.Flush(); flushErr != nil {
			return flushErr
		}

		produced = cw.n

		return nil
	})
	f.recordDownload(started, produced, err)
	if err != nil {
		return CachedPlaintext{}, err
	}

	if getMeta.Key == "" {
		if served, ok := f.servedEntry(ctx, key, id, p); ok {
			return served, nil
		}
	}

	meta := entryMetaFromRemote(getMeta)
	if hasContainer {
		meta.SHA256 = hdr.SHA256Hex()
	}

	out := cachedPlaintext(key, id, p, meta, false)

	out.Size = getMeta.ContentSize
	if out.Size == 0 {
		out.Size = getMeta.Size
	}

	if hasContainer {
		out.Size = hdr.PlaintextSize
	}
	// Populate wrote the sidecar before the body was read, so it has no identity.
	// Record it now: without this the next hit advertises the cache id as its
	// ETag, and revalidation has no digest to compare and re-downloads.
	// Best-effort by design — a failed patch only leaves the entry to the usual
	// soft-TTL revalidation.
	_ = f.cache.MarkValidated(ctx, id, meta)

	return out, nil
}

// servedEntry returns the cache entry another reader populated while this one
// was blocked in Populate. The sidecar is written before the body is read, so
// the owner may not have patched SHA256 yet; resolve it once here rather than
// returning an empty checksum to the client.
func (f *Fetch) servedEntry(ctx context.Context, key string, id port.CacheID, p string) (CachedPlaintext, bool) {
	_, stored, hit, err := f.cache.Lookup(ctx, id)
	if err != nil || !hit {
		return CachedPlaintext{}, false
	}

	if stored.SHA256 == "" {
		if remote, resolveErr := identity.ResolveRemote(ctx, f.store, key); resolveErr == nil && remote.Exists {
			stored = entryMetaFromRemote(remote)
			_ = f.cache.MarkValidated(ctx, id, stored)
		}
	}

	return cachedPlaintext(key, id, p, stored, false), true
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
// It returns the parsed container header (zero when absent) and the container's
// payload encryption name; objEnc is "" for legacy objects.
func unwrapForDecrypt(ctx context.Context, body io.Reader, meta domain.ObjectMeta) (
	context.Context, io.Reader, string, container.Header, bool, error,
) {
	hdr, payload, ok, err := container.Unwrap(body)
	if err != nil {
		return ctx, nil, "", container.Header{}, false, err
	}

	objEnc := ""
	tp := meta.CryptoProThumbprint // legacy user-metadata fallback
	if ok {
		objEnc = container.EncName(hdr.Enc)
		if ht := hdr.ThumbprintHex(); ht != "" {
			tp = ht
		}
	}

	return encrypt.WithCryptoProThumbprint(ctx, tp), payload, objEnc, hdr, ok, nil
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
	if encryptName(f.enc) == encrypt.NameNone {
		f.logger.Debug("object has no S3VCTR01 container (encryption.mode=none writes none); using magic/type detection",
			slog.String("key", key))

		return
	}

	f.logger.Warn("object has no S3VCTR01 container; falling back to legacy detection",
		slog.String("key", key))
}

// releasedFile is an open plaintext file that also releases the cache or
// ephemeral entry it belongs to when closed.
type releasedFile struct {
	*os.File
	release func()
}

func (r *releasedFile) Close() error {
	err := r.File.Close()
	if r.release != nil {
		r.release()
	}

	return err
}
