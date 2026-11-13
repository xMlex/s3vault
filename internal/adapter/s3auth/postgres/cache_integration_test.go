//go:build integration

package postgres

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/s3auth/secretbox"
	"github.com/xMlex/s3vault/internal/port"
)

// TestIntegrationLookupCache pins both halves of the TTL contract: a cached
// principal is served without the database until the TTL expires, and an
// in-process admin change drops it immediately.
func TestIntegrationLookupCache(t *testing.T) {
	dsn := os.Getenv("S3VAULT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("S3VAULT_TEST_POSTGRES_DSN is not set")
	}

	key, err := secretbox.ParseKey(testMasterKey)
	require.NoError(t, err)

	id, err := Open(t.Context(), Config{
		DSN:            dsn,
		MaxConns:       2,
		QueryTimeout:   2 * time.Second,
		MasterKey:      key,
		Bucket:         "s3vault",
		CacheTTL:       time.Minute,
		SkipValidation: true,
	})
	require.NoError(t, err)
	t.Cleanup(id.Close)
	require.NotNil(t, id.cache, "CacheTTL must enable the cache")

	truncateAll(t, id)

	user, _, err := id.AddUser(t.Context(), AddParams{Name: "cached", Prefix: "cached"})
	require.NoError(t, err)

	// Freeze time so the TTL boundary is deterministic.
	now := time.Unix(1700000000, 0)
	id.cache.now = func() time.Time { return now }

	_, ok, err := id.Lookup(t.Context(), user.AccessKeyID)
	require.NoError(t, err)
	require.True(t, ok)

	// A direct SQL edit bypasses the in-process invalidation, exactly like an
	// admin CLI in another process: the cached principal must survive until the
	// TTL, then the database must win.
	_, err = id.pool.Exec(t.Context(),
		"UPDATE s3vault_users SET enabled = false WHERE access_key_id = $1", user.AccessKeyID)
	require.NoError(t, err)

	_, ok, err = id.Lookup(t.Context(), user.AccessKeyID)
	require.NoError(t, err)
	assert.True(t, ok, "within the TTL the cached principal is served")

	now = now.Add(time.Minute)

	_, ok, err = id.Lookup(t.Context(), user.AccessKeyID)
	assert.False(t, ok, "after the TTL the disabled user is rejected")
	require.ErrorIs(t, err, port.ErrAccessDenied)

	// SetEnabled runs in-process and invalidates immediately, without waiting
	// for the TTL.
	require.NoError(t, id.SetEnabled(t.Context(), user.AccessKeyID, true))

	_, ok, err = id.Lookup(t.Context(), user.AccessKeyID)
	require.NoError(t, err)
	assert.True(t, ok, "an in-process change is visible at once")
}
