package service

import (
	"sync"
	"time"

	"github.com/xMlex/s3vault/internal/domain"
)

// defaultStatSizeMemoMax bounds statSizeMemo per process. Legacy objects are the
// only population, so the count stays small in practice; the bound keeps a
// pathological backend from growing the map forever.
const defaultStatSizeMemoMax = 4096

// statSizeMemo remembers the plaintext size of objects that Fetch.Stat can only
// size by materializing them: a legacy containerless object that declares no
// size. Without it every HEAD of such an object downloads and decrypts it again
// (measured at ~9 ms for 16 MiB); with it the download happens once per object
// version, and repeated HEADs are metadata-only again.
//
// Entries are keyed by the version the store reported. A changed ETag,
// LastModified or stored size is a miss and is re-materialized. An object with
// no validator at all is never memoized, because nothing could prove the cached
// size still belongs to it.
type statSizeMemo struct {
	mu      sync.Mutex
	entries map[statSizeKey]int64
	order   []statSizeKey
	max     int
}

type statSizeKey struct {
	key          string
	etag         string
	lastModified time.Time
	storedSize   int64
}

func newStatSizeMemo(limit int) *statSizeMemo {
	if limit <= 0 {
		limit = defaultStatSizeMemoMax
	}

	return &statSizeMemo{
		entries: make(map[statSizeKey]int64),
		max:     limit,
	}
}

func (m *statSizeMemo) lookup(key string, meta domain.ObjectMeta) (int64, bool) {
	if m == nil {
		return 0, false
	}

	k, ok := statSizeKeyOf(key, meta)
	if !ok {
		return 0, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	size, ok := m.entries[k]

	return size, ok
}

func (m *statSizeMemo) store(key string, meta domain.ObjectMeta, size int64) {
	if m == nil || size < 0 {
		return
	}

	k, ok := statSizeKeyOf(key, meta)
	if !ok {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.entries[k]; !exists {
		if len(m.order) >= m.max {
			oldest := m.order[0]
			m.order = m.order[1:]
			delete(m.entries, oldest)
		}

		m.order = append(m.order, k)
	}

	m.entries[k] = size
}

// statSizeKeyOf refuses to build a key without a version: a bare key would let
// an overwritten object keep answering with the previous plaintext size.
func statSizeKeyOf(key string, meta domain.ObjectMeta) (statSizeKey, bool) {
	if meta.ETag == "" && meta.LastModified.IsZero() {
		return statSizeKey{}, false
	}

	return statSizeKey{
		key:          key,
		etag:         meta.ETag,
		lastModified: meta.LastModified,
		storedSize:   meta.Size,
	}, true
}
