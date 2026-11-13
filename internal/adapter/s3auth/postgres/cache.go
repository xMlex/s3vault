package postgres

import (
	"sync"
	"time"

	"github.com/xMlex/s3vault/internal/port"
)

// maxPrincipalCacheEntries bounds the cache. Access keys are operator-created,
// so the map stays small in practice; the bound only guarantees that a leaked
// credential cannot grow it without limit.
const maxPrincipalCacheEntries = 4096

// principalCache remembers Lookup results for a short TTL, so a burst of
// requests with one access key does not repeat the joined query and the AES-GCM
// opening on every request. The TTL is the whole freshness contract: a rotated
// secret, a disabled user or a changed profile/target becomes visible within
// CacheTTL, never later.
//
// It is intentionally tiny: no persistence, no revalidation, no negative
// entries. A miss or an expired entry simply falls through to the database.
// A cached principal is treated as immutable: every request reads it, none may
// mutate its slices or target.
type principalCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	now     func() time.Time
	entries map[string]principalEntry
}

type principalEntry struct {
	principal port.Principal
	expires   time.Time
}

func newPrincipalCache(ttl time.Duration) *principalCache {
	return &principalCache{
		ttl:     ttl,
		now:     time.Now,
		entries: make(map[string]principalEntry),
	}
}

func (c *principalCache) get(accessKeyID string) (port.Principal, bool) {
	if c == nil {
		return port.Principal{}, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[accessKeyID]
	if !ok {
		return port.Principal{}, false
	}

	if !c.now().Before(entry.expires) {
		delete(c.entries, accessKeyID)

		return port.Principal{}, false
	}

	return entry.principal, true
}

func (c *principalCache) put(accessKeyID string, principal port.Principal) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= maxPrincipalCacheEntries {
		c.evictLocked()
	}

	c.entries[accessKeyID] = principalEntry{
		principal: principal,
		expires:   c.now().Add(c.ttl),
	}
}

// delete drops one entry. Admin operations call it so an in-process change is
// visible immediately instead of after the TTL; a separate CLI process cannot
// do this, which is exactly why the TTL is short.
func (c *principalCache) delete(accessKeyID string) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, accessKeyID)
}

// evictLocked drops expired entries, and clears the map if none expired. The
// second case needs a genuine flood of distinct access keys to reach; dropping
// everything then is simpler than tracking insertion order and stays correct.
func (c *principalCache) evictLocked() {
	now := c.now()

	for key, entry := range c.entries {
		if !now.Before(entry.expires) {
			delete(c.entries, key)
		}
	}

	if len(c.entries) >= maxPrincipalCacheEntries {
		clear(c.entries)
	}
}
