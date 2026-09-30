package localstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/domain"
)

// problems.md P5: when the raw-layout SHA-256 memo overflows it must evict the
// least-recently-used entry deterministically. The limit is shrunk to 2 so the
// test does not need 4096 objects.
func TestSHAMemoEvictsLeastRecentlyUsed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "objects")
	st, err := New(config.LocalConfig{Dir: dir, Layout: config.LocalLayoutRaw})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	st.shaCacheMax = 2

	for _, kv := range [][2]string{{"a", "aaa"}, {"b", "bbb"}, {"c", "ccc"}} {
		require.NoError(t, st.Put(ctx, kv[0], strings.NewReader(kv[1]), domain.PutMeta{}))
	}

	// Fill the memo (a, b), then touch a so b becomes least-recently-used.
	for _, key := range []string{"a", "b", "a"} {
		_, err := st.Head(ctx, key)
		require.NoError(t, err)
	}
	// Inserting c overflows the memo: b must be evicted, a must survive.
	_, err = st.Head(ctx, "c")
	require.NoError(t, err)

	// Overwrite a and b with equal-length bodies and restore the original mtime,
	// so only the memo decides whether the digest is stale. a is served from the
	// memo; b was evicted, so it is re-hashed.
	overwriteKeepingIdentity(t, dir, "a", "zzz")
	overwriteKeepingIdentity(t, dir, "b", "yyy")

	gotA, err := st.Head(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, sumHex("aaa"), gotA.SHA256, "recently used entry must survive and serve its memoized digest")

	gotB, err := st.Head(ctx, "b")
	require.NoError(t, err)
	assert.Equal(t, sumHex("yyy"), gotB.SHA256, "evicted entry must be recomputed, not left stale")
}

// overwriteKeepingIdentity rewrites a raw object in place with a same-length
// body and restores the previous mtime, reproducing the size+mtime identity the
// SHA memo keys on.
func overwriteKeepingIdentity(t *testing.T, dir, key, body string) {
	t.Helper()

	p := filepath.Join(dir, key)
	fi, err := os.Stat(p)
	require.NoError(t, err)
	require.Equal(t, fi.Size(), int64(len(body)), "same-length rewrite keeps the memo key stable")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	require.NoError(t, os.Chtimes(p, fi.ModTime(), fi.ModTime()))
}

func sumHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
