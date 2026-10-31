// Package digest is the gateway's persistent cache of plaintext SHA-256 and
// mtime for containerless local objects. It is a read-mostly point store: one
// pogreb database per shard, sharded by a hash of the object key. The index is
// derived state, never the identity source of truth: a miss or a broken index
// simply falls back to hashing the file.
package digest

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akrylysov/pogreb"

	localstore "github.com/xMlex/s3vault/internal/adapter/local"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/iocopy"
)

const (
	// DefaultShards matches config.DefaultLocalIndexShards; Open accepts any
	// value in [1, config.MaxLocalIndexShards].
	DefaultShards = config.DefaultLocalIndexShards
	// WarmWorkers is the fixed number of goroutines used by the first,
	// automatic full warm.
	WarmWorkers = 2
	// maintenanceInterval is how often one shard is compacted. Compact itself
	// is online and no-ops when no segment is fragmented enough, so a long
	// interval is safe. Exactly one shard is touched per tick.
	maintenanceInterval = 12 * time.Hour

	valueVersion = 1
	valueLen     = 1 + 8 + 8 + 32 + 4

	warmMarkerName    = ".warm.done"
	warmMarkerVersion = "1"
)

// Options configures the index.
type Options struct {
	// Dir is the index directory, normally <backend.local.dir>/.s3vault-index.
	Dir string
	// Shards is the number of independent pogreb databases. Zero means
	// DefaultShards.
	Shards int
	// Logger receives best-effort index failures. Nil uses slog.Default.
	Logger *slog.Logger
}

// Index is a set of sharded pogreb databases keyed by sha256(object key).
type Index struct {
	dir    string
	shards int
	log    *slog.Logger
	dbs    []*pogreb.DB
	mu     sync.RWMutex // guards dbs against Close while requests are in flight

	needsWarm bool

	startOnce sync.Once
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	next      atomic.Uint32
}

// Open opens or creates the index. A shard that cannot be opened is logged and
// left unavailable: its keys fall back to hashing, while the other shards keep
// working. If every shard fails, Open returns the first error so the caller can
// run without an index.
func Open(opts Options) (*Index, error) {
	shards, log, err := normalizeOptions(opts)
	if err != nil {
		return nil, err
	}

	missing, err := ensureIndexDir(opts.Dir)
	if err != nil {
		return nil, err
	}

	idx := &Index{
		dir:    opts.Dir,
		shards: shards,
		log:    log,
		dbs:    make([]*pogreb.DB, shards),
	}
	total, firstErr, err := idx.openShards()
	if err != nil {
		return nil, err
	}
	if firstErr != nil && total == 0 && allNil(idx.dbs) {
		return nil, fmt.Errorf("open digest index %s: %w", opts.Dir, firstErr)
	}

	idx.needsWarm = missing || !hasWarmMarker(opts.Dir, shards)

	return idx, nil
}

func normalizeOptions(opts Options) (int, *slog.Logger, error) {
	if opts.Dir == "" {
		return 0, nil, errors.New("digest index dir is required")
	}
	shards := opts.Shards
	if shards == 0 {
		shards = DefaultShards
	}
	if shards < 1 || shards > config.MaxLocalIndexShards {
		return 0, nil, fmt.Errorf("digest index shards: must be between 1 and %d, got %d",
			config.MaxLocalIndexShards, shards)
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return shards, log, nil
}

func ensureIndexDir(dir string) (bool, error) {
	missing := false
	if _, err := os.Stat(dir); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("stat digest index %s: %w", dir, err)
		}
		missing = true
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("mkdir digest index %s: %w", dir, err)
	}
	// pogreb creates its own directories 0755; keep the tree private even when
	// the target directory itself is group-readable.
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // directory mode
		return false, fmt.Errorf("chmod digest index %s: %w", dir, err)
	}
	return missing, nil
}

func (i *Index) openShards() (uint32, error, error) {
	pogrebOpts := &pogreb.Options{
		// The index is derived state. Let pogreb write through normally and
		// close cleanly; no background fsync or compaction is armed here.
		BackgroundSyncInterval:       0,
		BackgroundCompactionInterval: 0,
	}
	var (
		firstErr error
		total    uint32
	)
	for n := range i.shards {
		dir := filepath.Join(i.dir, fmt.Sprintf("%02d", n))
		db, err := pogreb.Open(dir, pogrebOpts)
		if err != nil {
			if strings.Contains(err.Error(), "database is locked") {
				// Another process owns this index. Opening the remaining shards
				// would only produce the same warning eight times; a second
				// gateway runs without an index rather than sharing pogreb's
				// single-writer files.
				_ = i.closeShards()
				return 0, nil, fmt.Errorf("open digest index %s: %w", i.dir, err)
			}
			if firstErr == nil {
				firstErr = err
			}
			i.log.Warn("digest shard unavailable", "op", "index", "shard", n, "err", err)
			continue
		}
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // directory mode
			i.log.Warn("digest shard chmod", "op", "index", "shard", n, "err", err)
		}
		i.dbs[n] = db
		total += db.Count()
	}
	return total, firstErr, nil
}

func allNil(dbs []*pogreb.DB) bool {
	for _, db := range dbs {
		if db != nil {
			return false
		}
	}
	return true
}

// Dir returns the index directory.
func (i *Index) Dir() string { return i.dir }

// Shards returns the configured shard count.
func (i *Index) Shards() int { return i.shards }

// NeedsWarm reports whether the index was created empty and the full first warm
// should run.
func (i *Index) NeedsWarm() bool { return i.needsWarm }

// Start launches the automatic first warm (when needed) and the maintenance
// scheduler. It may be called once. Both stop when ctx is cancelled or Close is
// called.
func (i *Index) Start(ctx context.Context, root string, workers int) {
	if ctx == nil {
		ctx = context.Background()
	}
	i.startOnce.Do(func() {
		ctx, i.cancel = context.WithCancel(ctx) //nolint:fatcontext // owned by Start, not by a loop
		if i.needsWarm {
			i.wg.Go(func() {
				i.log.Info("digest index warm started", "op", "index", "root", root, "workers", workers)
				err := i.Warm(ctx, root, workers)
				if err != nil {
					if !errors.Is(err, context.Canceled) {
						i.log.Error("digest index warm", "op", "index", "err", err)
					}
					return
				}
				i.log.Info("digest index warm finished", "op", "index", "root", root)
			})
		}
		i.wg.Go(func() {
			i.maintain(ctx)
		})
	})
}

// Close stops background work and closes every shard.
func (i *Index) Close() error {
	if i.cancel != nil {
		i.cancel()
	}
	i.wg.Wait()

	i.mu.Lock()
	defer i.mu.Unlock()
	return i.closeShards()
}

func (i *Index) closeShards() error {
	var firstErr error
	for n, db := range i.dbs {
		if db == nil {
			continue
		}
		if err := db.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close digest shard %d: %w", n, err)
		}
		i.dbs[n] = nil
	}
	return firstErr
}

// Lookup returns the cached digest when the entry matches size and mtime.
func (i *Index) Lookup(key string, size int64, mtime time.Time) (string, bool) {
	h := sha256.Sum256([]byte(key))
	i.mu.RLock()
	db := i.shardForHash(h)
	if db == nil {
		i.mu.RUnlock()
		return "", false
	}
	// The shard key is the same 32-byte object-key hash, so a collision would
	// have to collide in the index key itself; the value's size/mtime check below
	// makes a wrong answer even less likely.
	val, err := db.Get(h[:])
	i.mu.RUnlock()
	if err != nil || val == nil {
		return "", false
	}
	gotSize, gotMtime, sum, ok := decodeValue(val)
	if !ok || gotSize != size || gotMtime != mtime.UnixNano() {
		return "", false
	}
	return sum, true
}

// Store writes a digest for key. Failures are logged at debug and ignored: the
// index is a cache.
func (i *Index) Store(key string, size int64, mtime time.Time, sum string) {
	val, ok := encodeValue(size, mtime.UnixNano(), sum)
	if !ok {
		return
	}
	h := sha256.Sum256([]byte(key))
	i.mu.RLock()
	db := i.shardForHash(h)
	if db == nil {
		i.mu.RUnlock()
		return
	}
	err := db.Put(h[:], val)
	i.mu.RUnlock()
	if err != nil {
		i.log.Debug("digest store", "op", "index", "err", err)
	}
}

// Delete removes a digest. A miss is a no-op.
func (i *Index) Delete(key string) {
	h := sha256.Sum256([]byte(key))
	i.mu.RLock()
	db := i.shardForHash(h)
	if db == nil {
		i.mu.RUnlock()
		return
	}
	err := db.Delete(h[:])
	i.mu.RUnlock()
	if err != nil {
		i.log.Debug("digest delete", "op", "index", "err", err)
	}
}

func (i *Index) shardForHash(h [sha256.Size]byte) *pogreb.DB {
	if len(i.dbs) == 0 {
		return nil
	}
	return i.dbs[int(h[0])%len(i.dbs)]
}

func encodeValue(size, mtimeNS int64, sumHex string) ([]byte, bool) {
	sum, err := hex.DecodeString(sumHex)
	if err != nil || len(sum) != sha256.Size {
		return nil, false
	}
	b := make([]byte, 0, valueLen)
	b = append(b, valueVersion)
	b = binary.LittleEndian.AppendUint64(b, uint64(size))    //nolint:gosec // fixed-width round trip
	b = binary.LittleEndian.AppendUint64(b, uint64(mtimeNS)) //nolint:gosec // fixed-width round trip
	b = append(b, sum...)
	b = binary.LittleEndian.AppendUint32(b, crc32.ChecksumIEEE(b))
	return b, true
}

func decodeValue(b []byte) (size, mtimeNS int64, sum string, ok bool) {
	if len(b) != valueLen || b[0] != valueVersion {
		return 0, 0, "", false
	}
	body := b[:valueLen-4]
	if crc32.ChecksumIEEE(body) != binary.LittleEndian.Uint32(b[valueLen-4:]) {
		return 0, 0, "", false
	}
	size = int64(binary.LittleEndian.Uint64(b[1:]))    //nolint:gosec // fixed-width round trip
	mtimeNS = int64(binary.LittleEndian.Uint64(b[9:])) //nolint:gosec // fixed-width round trip
	return size, mtimeNS, hex.EncodeToString(b[17:49]), true
}

// Warm walks root and fills every missing digest using workers goroutines. It
// skips the reserved index and temp directories, symlinks and non-regular
// files. It is safe to run while the server is serving: the index is a cache.
func (i *Index) Warm(ctx context.Context, root string, workers int) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if workers <= 0 {
		workers = WarmWorkers
	}
	rootDir, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("warm digest index: %w", err)
	}
	defer func() { _ = rootDir.Close() }()

	files := make(chan string)
	var wg sync.WaitGroup
	i.startWarmWorkers(ctx, rootDir, files, workers, &wg)

	err = i.walkWarm(ctx, root, files)
	close(files)
	wg.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("warm digest index: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writeWarmMarker(i.dir, i.shards); err != nil {
		// The warm itself succeeded; only the "completed" marker is missing, so
		// the next start will warm again and skip the entries already present.
		i.log.Warn("digest warm marker", "op", "index", "err", err)
	}
	return nil
}

func (i *Index) startWarmWorkers(ctx context.Context, root *os.Root, files <-chan string, workers int, wg *sync.WaitGroup) {
	for range workers {
		wg.Go(func() {
			for key := range files {
				i.hashOne(ctx, root, key)
			}
		})
	}
}

func (i *Index) walkWarm(ctx context.Context, root string, files chan<- string) error {
	return fs.WalkDir(os.DirFS(root), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			i.log.Warn("digest warm walk", "op", "index", "path", p, "err", err)
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if p == "." {
				return nil
			}
			if d.Name() == localstore.IndexDirName || d.Name() == localstore.TmpDirName {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		select {
		case files <- p:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	})
}

func hasWarmMarker(dir string, shards int) bool {
	b, err := os.ReadFile(filepath.Join(dir, warmMarkerName)) //nolint:gosec // index-owned path
	return err == nil && string(b) == warmMarker(shards)
}

func warmMarker(shards int) string {
	return warmMarkerVersion + ":" + strconv.Itoa(shards) + "\n"
}

func writeWarmMarker(dir string, shards int) error {
	tmp := filepath.Join(dir, warmMarkerName+".tmp")
	if err := os.WriteFile(tmp, []byte(warmMarker(shards)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, warmMarkerName))
}

func isContainerObject(f *os.File) (bool, error) {
	// Container objects already carry the digest in S3VCTR01; indexing them
	// would be wasted I/O. Only containerless (mode=none) objects need hashing.
	var head [container.HeaderSize]byte
	n, err := f.ReadAt(head[:], 0)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return false, err
	}
	if n != container.HeaderSize || !container.IsMagic(head[:]) {
		return false, nil
	}
	_, parseErr := container.Parse(head[:])
	return parseErr == nil, nil
}

func (i *Index) hashOne(ctx context.Context, root *os.Root, key string) {
	rel := filepath.FromSlash(key)
	fi, err := root.Stat(rel)
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	if _, ok := i.Lookup(key, fi.Size(), fi.ModTime()); ok {
		return
	}

	f, err := root.Open(rel)
	if err != nil {
		i.log.Debug("digest warm open", "op", "index", "key", key, "err", err)
		return
	}
	defer func() { _ = f.Close() }()

	if isContainer, err := isContainerObject(f); err != nil || isContainer {
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return
	}

	h := sha256.New()
	if _, err := iocopy.Copy(h, &contextReader{ctx: ctx, r: f}); err != nil {
		if !errors.Is(err, context.Canceled) {
			i.log.Debug("digest warm hash", "op", "index", "key", key, "err", err)
		}
		return
	}
	after, err := f.Stat()
	if err != nil {
		return
	}
	if after.Size() != fi.Size() || !after.ModTime().Equal(fi.ModTime()) {
		// The file changed while it was read; do not cache a digest that never
		// described one complete version.
		return
	}
	i.Store(key, after.Size(), after.ModTime(), hex.EncodeToString(h.Sum(nil)))
}

func (i *Index) maintain(ctx context.Context) {
	ticker := time.NewTicker(maintenanceInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			i.compactNext()
		}
	}
}

// compactNext compacts exactly one shard, round-robin. pogreb's Compact is
// online: it does not close the database, readers and writers keep working, and
// only the source segment is marked full.
func (i *Index) compactNext() {
	if len(i.dbs) == 0 {
		return
	}
	n := int(i.next.Add(1)-1) % len(i.dbs)
	i.mu.RLock()
	db := i.dbs[n]
	i.mu.RUnlock()
	if db == nil {
		return
	}
	cr, err := db.Compact()
	if err != nil {
		if !strings.Contains(err.Error(), "busy") {
			i.log.Warn("digest compact", "op", "index", "shard", n, "err", err)
		}
		return
	}
	if cr.CompactedSegments > 0 {
		i.log.Info("digest compacted",
			"op", "index", "shard", n,
			"segments", cr.CompactedSegments,
			"records", cr.ReclaimedRecords,
			"bytes", cr.ReclaimedBytes)
	}
}

//nolint:containedctx // request-scoped reader; ctx is the cancellation source
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
