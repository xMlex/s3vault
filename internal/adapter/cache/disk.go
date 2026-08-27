package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/xMlex/s3vault/internal/port"
)

// metaTmpSeq makes concurrent sidecar writes use distinct temp names.
var metaTmpSeq atomic.Uint64

const (
	hexIDLen = sha256HexLen
	shardLen = 2
	// atimeFlushInterval limits sidecar rewrites on cache hits (LRU only needs coarse atime).
	atimeFlushInterval = time.Minute
)

const sha256HexLen = 64

// Disk is a plaintext cache under a dedicated directory (os.Root).
//
// An in-memory index tracks live entries for O(1) Usage, in-memory LRU eviction,
// and Get hits without re-reading JSON sidecars. The index is loaded from disk
// at New and updated on Populate / Get / remove / Clear.
type Disk struct {
	root     *os.Root
	dir      string
	ttl      time.Duration
	maxBytes int64
	group    singleflight.Group
	evictMu  sync.Mutex

	idxMu      sync.RWMutex
	index      map[string]indexEntry // key = 64-hex cache id
	totalBytes int64
}

var _ port.PlaintextCache = (*Disk)(nil)

type sidecar struct {
	Size         int64     `json:"size"`
	CachedAt     time.Time `json:"cached_at"`
	ATime        time.Time `json:"atime"`
	ExpiresAt    time.Time `json:"expires_at"`
	ETag         string    `json:"etag,omitempty"`
	SHA256       string    `json:"sha256,omitempty"`
	LastModified time.Time `json:"last_modified,omitempty"`
	ValidatedAt  time.Time `json:"validated_at,omitempty"`
}

type indexEntry struct {
	absPath      string
	dataRel      string
	metaRel      string
	size         int64
	atime        time.Time
	expiresAt    time.Time
	cachedAt     time.Time
	etag         string
	sha256       string
	lastModified time.Time
	validatedAt  time.Time
}

// Options configure Disk.
type Options struct {
	Dir      string
	TTL      time.Duration
	MaxBytes int64
}

// New creates the cache directory (0700) and opens it with os.Root.
func New(opt Options) (*Disk, error) {
	if opt.Dir == "" {
		return nil, fmt.Errorf("cache dir is required")
	}
	if err := os.MkdirAll(opt.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir cache: %w", err)
	}
	if err := os.Chmod(opt.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod cache: %w", err)
	}
	root, err := os.OpenRoot(opt.Dir)
	if err != nil {
		return nil, fmt.Errorf("open cache root: %w", err)
	}
	d := &Disk{
		root:     root,
		dir:      opt.Dir,
		ttl:      opt.TTL,
		maxBytes: opt.MaxBytes,
		index:    make(map[string]indexEntry),
	}
	if err := d.loadIndex(); err != nil {
		_ = root.Close()
		return nil, err
	}
	return d, nil
}

// Close releases the directory file descriptor.
func (d *Disk) Close() error {
	if d.root == nil {
		return nil
	}
	return d.root.Close()
}

// Dir returns the cache root path.
func (d *Disk) Dir() string { return d.dir }

func (d *Disk) rel(id port.CacheID) (data, meta, lock, tmp string, err error) {
	s := string(id)
	if !validCacheID(s) {
		return "", "", "", "", fmt.Errorf("invalid cache id")
	}
	base := s[:shardLen] + "/" + s
	return base, base + ".meta", base + ".lock", base + ".tmp", nil
}

func validCacheID(s string) bool {
	return len(s) == hexIDLen && isHex(s)
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// Get returns the plaintext path if a live cache entry exists.
func (d *Disk) Get(ctx context.Context, id port.CacheID) (string, bool, error) {
	p, _, hit, err := d.Lookup(ctx, id)
	return p, hit, err
}

// Lookup returns path and sidecar identity meta for a live cache entry.
func (d *Disk) Lookup(ctx context.Context, id port.CacheID) (string, port.EntryMeta, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", port.EntryMeta{}, false, err
	}
	key := string(id)
	if !validCacheID(key) {
		return "", port.EntryMeta{}, false, fmt.Errorf("invalid cache id")
	}

	now := time.Now().UTC()
	if p, meta, ok := d.lookupIndexed(key, now); ok {
		return p, meta, true, nil
	}

	dataRel, metaRel, _, _, err := d.rel(id)
	if err != nil {
		return "", port.EntryMeta{}, false, err
	}
	sc, err := d.readMeta(metaRel)
	if err != nil {
		if os.IsNotExist(err) {
			return "", port.EntryMeta{}, false, nil
		}
		// Torn/corrupt sidecar (e.g. pre-fix concurrent atime writes): drop and miss.
		_ = d.removeEntry(key, dataRel, metaRel)
		return "", port.EntryMeta{}, false, nil
	}
	if expired(sc, now) {
		_ = d.removeEntry(key, dataRel, metaRel)
		return "", port.EntryMeta{}, false, nil
	}
	if _, err := d.root.Stat(dataRel); err != nil {
		if os.IsNotExist(err) {
			_ = d.root.Remove(metaRel)
			d.forget(key)
			return "", port.EntryMeta{}, false, nil
		}
		return "", port.EntryMeta{}, false, err
	}
	d.remember(key, dataRel, metaRel, sc)
	if sc.ATime.IsZero() || now.Sub(sc.ATime) >= atimeFlushInterval {
		sc.ATime = now
		d.touch(key, sc.ATime)
		_ = d.writeMeta(metaRel, sc)
	}
	return d.abs(dataRel), entryMetaFromSidecar(sc), true, nil
}

// Remove drops a plaintext cache entry if present (best-effort after DeleteObject).
func (d *Disk) Remove(ctx context.Context, id port.CacheID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dataRel, metaRel, _, _, err := d.rel(id)
	if err != nil {
		return err
	}
	return d.removeEntry(string(id), dataRel, metaRel)
}

// MarkValidated refreshes soft-TTL identity fields without rewriting plaintext.
func (d *Disk) MarkValidated(ctx context.Context, id port.CacheID, meta port.EntryMeta) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := string(id)
	if !validCacheID(key) {
		return fmt.Errorf("invalid cache id")
	}
	dataRel, metaRel, _, _, err := d.rel(id)
	if err != nil {
		return err
	}
	sc, err := d.readMeta(metaRel)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if meta.ETag != "" {
		sc.ETag = meta.ETag
	}
	if meta.SHA256 != "" {
		sc.SHA256 = meta.SHA256
	}
	if !meta.LastModified.IsZero() {
		sc.LastModified = meta.LastModified
	}
	if !meta.ValidatedAt.IsZero() {
		sc.ValidatedAt = meta.ValidatedAt.UTC()
	} else {
		sc.ValidatedAt = now
	}
	sc.ATime = now
	if err := d.writeMeta(metaRel, sc); err != nil {
		return err
	}
	d.remember(key, dataRel, metaRel, sc)
	return nil
}

// lookupIndexed serves a hit from the in-memory index (no JSON/stat I/O).
// Returns ("", {}, false) on miss or if the entry was expired and dropped.
func (d *Disk) lookupIndexed(key string, now time.Time) (string, port.EntryMeta, bool) {
	d.idxMu.RLock()
	e, ok := d.index[key]
	d.idxMu.RUnlock()
	if !ok {
		return "", port.EntryMeta{}, false
	}
	if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
		_ = d.removeEntry(key, e.dataRel, e.metaRel)
		return "", port.EntryMeta{}, false
	}
	meta := port.EntryMeta{
		ETag:         e.etag,
		SHA256:       e.sha256,
		LastModified: e.lastModified,
		ValidatedAt:  e.validatedAt,
	}
	if e.atime.IsZero() || now.Sub(e.atime) >= atimeFlushInterval {
		sc := sidecar{
			Size:         e.size,
			CachedAt:     e.cachedAt,
			ATime:        now,
			ExpiresAt:    e.expiresAt,
			ETag:         e.etag,
			SHA256:       e.sha256,
			LastModified: e.lastModified,
			ValidatedAt:  e.validatedAt,
		}
		d.touch(key, now)
		_ = d.writeMeta(e.metaRel, sc)
	}
	return e.absPath, meta, true
}

func entryMetaFromSidecar(sc sidecar) port.EntryMeta {
	return port.EntryMeta{
		ETag:         sc.ETag,
		SHA256:       sc.SHA256,
		LastModified: sc.LastModified,
		ValidatedAt:  sc.ValidatedAt,
	}
}

// entryUnchanged is true when Populate may keep the existing plaintext.
// Empty want identity means "any cached body is fine" (stampede / warm hit).
func entryUnchanged(stored, want port.EntryMeta) bool {
	if want.SHA256 == "" && want.ETag == "" {
		return true
	}
	if want.SHA256 != "" && stored.SHA256 != "" {
		return want.SHA256 == stored.SHA256
	}
	if want.ETag != "" && stored.ETag != "" {
		return want.ETag == stored.ETag
	}
	return false
}

func expired(sc sidecar, now time.Time) bool {
	return !sc.ExpiresAt.IsZero() && !now.Before(sc.ExpiresAt)
}

func (d *Disk) abs(rel string) string {
	return filepath.Join(d.dir, filepath.FromSlash(rel))
}

func (d *Disk) readMeta(rel string) (sidecar, error) {
	b, err := d.root.ReadFile(rel)
	if err != nil {
		return sidecar{}, err
	}
	var sc sidecar
	if err := json.Unmarshal(b, &sc); err != nil {
		return sidecar{}, fmt.Errorf("cache meta: %w", err)
	}
	return sc, nil
}

func (d *Disk) writeMeta(rel string, sc sidecar) error {
	b, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	// Unique tmp + rename: concurrent Get atime updates must not tear the JSON.
	tmpRel := rel + "." + strconv.FormatUint(metaTmpSeq.Add(1), 10) + ".tmp"
	if err := d.root.WriteFile(tmpRel, b, 0o600); err != nil {
		return err
	}
	if err := d.root.Rename(tmpRel, rel); err != nil {
		_ = d.root.Remove(tmpRel)
		return err
	}
	return nil
}

func (d *Disk) removeEntry(key, dataRel, metaRel string) error {
	err1 := d.root.Remove(dataRel)
	err2 := d.root.Remove(metaRel)
	d.forget(key)
	if err1 != nil && !os.IsNotExist(err1) {
		return err1
	}
	if err2 != nil && !os.IsNotExist(err2) {
		return err2
	}
	return nil
}

func (d *Disk) remember(key, dataRel, metaRel string, sc sidecar) {
	d.idxMu.Lock()
	defer d.idxMu.Unlock()
	if old, ok := d.index[key]; ok {
		d.totalBytes -= old.size
	}
	d.index[key] = indexEntry{
		absPath:      d.abs(dataRel),
		dataRel:      dataRel,
		metaRel:      metaRel,
		size:         sc.Size,
		atime:        sc.ATime,
		expiresAt:    sc.ExpiresAt,
		cachedAt:     sc.CachedAt,
		etag:         sc.ETag,
		sha256:       sc.SHA256,
		lastModified: sc.LastModified,
		validatedAt:  sc.ValidatedAt,
	}
	d.totalBytes += sc.Size
}

func (d *Disk) touch(key string, atime time.Time) {
	d.idxMu.Lock()
	defer d.idxMu.Unlock()
	if e, ok := d.index[key]; ok {
		e.atime = atime
		d.index[key] = e
	}
}

func (d *Disk) forget(key string) {
	d.idxMu.Lock()
	defer d.idxMu.Unlock()
	if e, ok := d.index[key]; ok {
		d.totalBytes -= e.size
		delete(d.index, key)
	}
}

func (d *Disk) loadIndex() error {
	entries, _, err := d.listEntries()
	if err != nil {
		return fmt.Errorf("load cache index: %w", err)
	}
	d.idxMu.Lock()
	defer d.idxMu.Unlock()
	d.index = make(map[string]indexEntry, len(entries))
	d.totalBytes = 0
	for _, e := range entries {
		key := path.Base(e.dataRel)
		d.index[key] = indexEntry{
			absPath:      d.abs(e.dataRel),
			dataRel:      e.dataRel,
			metaRel:      e.metaRel,
			size:         e.size,
			atime:        e.atime,
			expiresAt:    e.expiresAt,
			cachedAt:     e.cachedAt,
			etag:         e.etag,
			sha256:       e.sha256,
			lastModified: e.lastModified,
			validatedAt:  e.validatedAt,
		}
		d.totalBytes += e.size
	}
	return nil
}

// Populate decrypts into the cache once per id+identity (singleflight + lockfile).
func (d *Disk) Populate(ctx context.Context, id port.CacheID, meta port.EntryMeta, fill func(w io.Writer) error) (string, error) {
	flight := string(id) + "\x00" + meta.SHA256 + "\x00" + meta.ETag
	v, err, _ := d.group.Do(flight, func() (any, error) {
		return d.populate(ctx, id, meta, fill)
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (d *Disk) populate(ctx context.Context, id port.CacheID, meta port.EntryMeta, fill func(w io.Writer) error) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if p, stored, hit, err := d.Lookup(ctx, id); err != nil {
		return "", err
	} else if hit && entryUnchanged(stored, meta) {
		return p, nil
	}

	dataRel, metaRel, lockRel, tmpRel, err := d.rel(id)
	if err != nil {
		return "", err
	}
	if err := d.root.MkdirAll(string(id)[:shardLen], 0o700); err != nil {
		return "", fmt.Errorf("mkdir shard: %w", err)
	}

	lf, err := d.root.OpenFile(lockRel, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return "", fmt.Errorf("cache lock: %w", err)
	}
	if err := lockExclusive(lf); err != nil {
		_ = lf.Close()
		return "", err
	}
	defer func() {
		_ = unlockExclusive(lf)
		_ = lf.Close()
	}()

	if p, stored, hit, err := d.Lookup(ctx, id); err != nil {
		return "", err
	} else if hit && entryUnchanged(stored, meta) {
		return p, nil
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	tf, err := d.root.OpenFile(tmpRel, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("cache tmp: %w", err)
	}
	tmpOK := false
	defer func() {
		if !tmpOK {
			_ = d.root.Remove(tmpRel)
		}
	}()
	if err := fill(tf); err != nil {
		_ = tf.Close()
		return "", err
	}
	if err := tf.Sync(); err != nil {
		_ = tf.Close()
		return "", fmt.Errorf("fsync cache: %w", err)
	}
	st, err := tf.Stat()
	if err != nil {
		_ = tf.Close()
		return "", err
	}
	if err := tf.Close(); err != nil {
		return "", err
	}
	if err := d.root.Chmod(tmpRel, 0o600); err != nil {
		return "", err
	}
	if err := d.root.Rename(tmpRel, dataRel); err != nil {
		return "", fmt.Errorf("rename cache: %w", err)
	}
	tmpOK = true

	now := time.Now().UTC()
	sc := sidecar{
		Size:         st.Size(),
		CachedAt:     now,
		ATime:        now,
		ETag:         meta.ETag,
		SHA256:       meta.SHA256,
		LastModified: meta.LastModified,
		ValidatedAt:  meta.ValidatedAt,
	}
	if sc.ValidatedAt.IsZero() {
		sc.ValidatedAt = now
	}
	if d.ttl > 0 {
		sc.ExpiresAt = now.Add(d.ttl)
	}
	if err := d.writeMeta(metaRel, sc); err != nil {
		_ = d.removeEntry(string(id), dataRel, metaRel)
		return "", err
	}
	d.remember(string(id), dataRel, metaRel, sc)
	d.evict()
	return d.abs(dataRel), nil
}

type entry struct {
	dataRel      string
	metaRel      string
	atime        time.Time
	size         int64
	expiresAt    time.Time
	cachedAt     time.Time
	etag         string
	sha256       string
	lastModified time.Time
	validatedAt  time.Time
}

func (d *Disk) evict() {
	if d.maxBytes <= 0 {
		return
	}
	d.evictMu.Lock()
	defer d.evictMu.Unlock()

	d.idxMu.RLock()
	if d.totalBytes <= d.maxBytes {
		d.idxMu.RUnlock()
		return
	}
	entries := make([]entry, 0, len(d.index))
	for _, e := range d.index {
		entries = append(entries, entry{
			dataRel: e.dataRel,
			metaRel: e.metaRel,
			atime:   e.atime,
			size:    e.size,
		})
	}
	total := d.totalBytes
	d.idxMu.RUnlock()

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].atime.Before(entries[j].atime)
	})
	for _, e := range entries {
		if total <= d.maxBytes {
			return
		}
		key := path.Base(e.dataRel)
		_ = d.removeEntry(key, e.dataRel, e.metaRel)
		total -= e.size
	}
}

func (d *Disk) listEntries() ([]entry, int64, error) {
	dirf, err := d.root.Open(".")
	if err != nil {
		return nil, 0, err
	}
	defer dirf.Close()
	shards, err := dirf.ReadDir(-1)
	if err != nil {
		return nil, 0, err
	}
	var out []entry
	var total int64
	for _, sh := range shards {
		if !sh.IsDir() || len(sh.Name()) != shardLen || !isHex(sh.Name()) {
			continue
		}
		sf, err := d.root.Open(sh.Name())
		if err != nil {
			continue
		}
		names, err := sf.ReadDir(-1)
		_ = sf.Close()
		if err != nil {
			continue
		}
		for _, n := range names {
			name := n.Name()
			if n.IsDir() || strings.Contains(name, ".") {
				continue
			}
			if len(name) != hexIDLen || !isHex(name) {
				continue
			}
			dataRel := sh.Name() + "/" + name
			metaRel := dataRel + ".meta"
			sc, err := d.readMeta(metaRel)
			if err != nil {
				continue
			}
			out = append(out, entry{
				dataRel:      dataRel,
				metaRel:      metaRel,
				atime:        sc.ATime,
				size:         sc.Size,
				expiresAt:    sc.ExpiresAt,
				cachedAt:     sc.CachedAt,
				etag:         sc.ETag,
				sha256:       sc.SHA256,
				lastModified: sc.LastModified,
				validatedAt:  sc.ValidatedAt,
			})
			total += sc.Size
		}
	}
	return out, total, nil
}

// Stats is aggregate cache usage.
type Stats struct {
	Entries int   `json:"entries"`
	Bytes   int64 `json:"bytes"`
}

// Usage returns indexed cache occupancy (O(1); no directory walk).
func (d *Disk) Usage() (Stats, error) {
	d.idxMu.RLock()
	defer d.idxMu.RUnlock()
	return Stats{Entries: len(d.index), Bytes: d.totalBytes}, nil
}

// SweepExpired removes hard-TTL expired entries from disk and the in-memory index.
// Entries with a zero ExpiresAt (TTL disabled at Populate) are left alone.
func (d *Disk) SweepExpired() int {
	now := time.Now().UTC()
	type doomed struct {
		key, dataRel, metaRel string
	}
	d.idxMu.RLock()
	list := make([]doomed, 0)
	for key, e := range d.index {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			list = append(list, doomed{key: key, dataRel: e.dataRel, metaRel: e.metaRel})
		}
	}
	d.idxMu.RUnlock()

	n := 0
	for _, e := range list {
		if err := d.removeEntry(e.key, e.dataRel, e.metaRel); err != nil {
			continue
		}
		n++
	}
	return n
}

// StartSweeper runs SweepExpired every interval until ctx is cancelled.
// The first sweep runs immediately. interval <= 0 is a no-op.
func (d *Disk) StartSweeper(ctx context.Context, interval time.Duration, log *slog.Logger) {
	if interval <= 0 || d == nil {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	go d.sweepLoop(ctx, interval, log)
}

func (d *Disk) sweepLoop(ctx context.Context, interval time.Duration, log *slog.Logger) {
	run := func() {
		n := d.SweepExpired()
		if n > 0 {
			log.InfoContext(ctx, "cache sweep",
				slog.String("op", "cache"),
				slog.Int("removed", n),
			)
		}
	}
	run()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// Clear deletes cached plaintext (keeps the root directory).
func (d *Disk) Clear() error {
	dirf, err := d.root.Open(".")
	if err != nil {
		return err
	}
	defer dirf.Close()
	names, err := dirf.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, n := range names {
		if err := d.root.RemoveAll(n.Name()); err != nil {
			return err
		}
	}
	d.idxMu.Lock()
	d.index = make(map[string]indexEntry)
	d.totalBytes = 0
	d.idxMu.Unlock()
	return nil
}
