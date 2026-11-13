package postgres

import (
	"strconv"
	"testing"
	"time"

	"github.com/xMlex/s3vault/internal/port"
)

// BenchmarkPrincipalCacheHit is the replacement cost for a cached Lookup: a
// mutex, a map read and an expiry comparison, against ~157 µs for the database
// path (BenchmarkIdentityLookup).
func BenchmarkPrincipalCacheHit(b *testing.B) {
	cache := newPrincipalCache(time.Minute)
	cache.put("ak", port.Principal{AccessKeyID: "ak", SecretKey: "secret"})

	b.ReportAllocs()

	for b.Loop() {
		if _, ok := cache.get("ak"); !ok {
			b.Fatal("cache miss")
		}
	}
}

func BenchmarkPrincipalCachePut(b *testing.B) {
	cache := newPrincipalCache(time.Minute)

	b.ReportAllocs()

	for i := range b.N {
		cache.put(strconv.Itoa(i), port.Principal{AccessKeyID: "ak"})
	}
}
