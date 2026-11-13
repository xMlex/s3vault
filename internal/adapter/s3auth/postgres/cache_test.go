package postgres

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/xMlex/s3vault/internal/port"
)

func TestPrincipalCacheHonoursTTL(t *testing.T) {
	t.Parallel()

	now := time.Unix(1000, 0)
	cache := newPrincipalCache(time.Second)
	cache.now = func() time.Time { return now }

	principal := port.Principal{AccessKeyID: "ak", SecretKey: "secret"}
	cache.put("ak", principal)

	got, ok := cache.get("ak")
	assert.True(t, ok)
	assert.Equal(t, principal, got)

	now = now.Add(time.Second)

	_, ok = cache.get("ak")
	assert.False(t, ok, "an entry expires at the TTL boundary")
}

func TestPrincipalCacheDelete(t *testing.T) {
	t.Parallel()

	cache := newPrincipalCache(time.Minute)
	cache.put("ak", port.Principal{AccessKeyID: "ak"})
	cache.delete("ak")

	_, ok := cache.get("ak")
	assert.False(t, ok)
}

func TestPrincipalCacheNilIsNoop(t *testing.T) {
	t.Parallel()

	var cache *principalCache

	_, ok := cache.get("ak")
	assert.False(t, ok)

	cache.put("ak", port.Principal{})
	cache.delete("ak")
}

func TestPrincipalCacheStaysBounded(t *testing.T) {
	t.Parallel()

	cache := newPrincipalCache(time.Minute)

	for i := range maxPrincipalCacheEntries + 10 {
		key := strconv.Itoa(i)
		cache.put(key, port.Principal{AccessKeyID: key})
	}

	cache.mu.Lock()
	size := len(cache.entries)
	cache.mu.Unlock()

	assert.LessOrEqual(t, size, maxPrincipalCacheEntries)
}
