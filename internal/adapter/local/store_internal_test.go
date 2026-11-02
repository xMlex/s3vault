package localstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	st, err := New(config.LocalConfig{Dir: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	st.shaCacheMax = 2

	for _, kv := range [][2]string{{"a", "aaa"}, {"b", "bbb"}, {"c", "ccc"}} {
		require.NoError(t, st.Put(ctx, kv[0], strings.NewReader(kv[1]), domain.PutMeta{}))
	}

	// Fill the memo (a, b), then touch a so b becomes least-recently-used.
	for _, key := range []string{"a", "b", "a", "c"} {
		_, err := st.Head(ctx, key)
		require.NoError(t, err)
	}

	// Inserting c overflows the memo: b must be evicted, a and c must survive.
	st.shaMu.Lock()
	defer st.shaMu.Unlock()

	assert.Contains(t, st.shaCache, "a")
	assert.Contains(t, st.shaCache, "c")
	assert.NotContains(t, st.shaCache, "b", "least-recently-used entry must be evicted")
}

// A sync tool that restores timestamps rewrites the bytes while keeping size
// and mtime, so the memo must compare the full file version, not those two
// fields alone.
func TestSHAMemoInvalidatesSameSizeSameMTimeOverwrite(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "objects")
	st, err := New(config.LocalConfig{Dir: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	mtime := time.Unix(1_700_000_000, 0).UTC()
	p := filepath.Join(dir, "a")
	require.NoError(t, os.WriteFile(p, []byte("aaa"), 0o600))
	require.NoError(t, os.Chtimes(p, mtime, mtime))

	first, err := st.Head(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, sumHex("aaa"), first.SHA256)

	overwriteKeepingIdentity(t, dir, "a", "zzz")

	second, err := st.Head(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, sumHex("zzz"), second.SHA256, "a rewritten file must never serve its previous digest")
}

// overwriteKeepingIdentity rewrites a raw object in place with a same-length
// body and restores the previous mtime, reproducing the size+mtime identity
// older cache keys used. The inode change time still advances, which is what
// makes the new version distinguishable.
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
