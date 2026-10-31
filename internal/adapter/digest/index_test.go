package digest_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/digest"
	localstore "github.com/xMlex/s3vault/internal/adapter/local"
)

func TestIndexPersistsAndValidatesStat(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	idx, err := digest.Open(digest.Options{Dir: filepath.Join(root, localstore.IndexDirName), Shards: 4})
	require.NoError(t, err)

	sum := sha256.Sum256([]byte("payload"))
	hexSum := hex.EncodeToString(sum[:])
	now := time.Now().UTC()
	idx.Store("2023/10/09/video.mp4", 7, now, hexSum)

	got, ok := idx.Lookup("2023/10/09/video.mp4", 7, now)
	require.True(t, ok)
	assert.Equal(t, hexSum, got)

	_, ok = idx.Lookup("2023/10/09/video.mp4", 8, now)
	assert.False(t, ok, "size mismatch must be a miss")

	_, ok = idx.Lookup("2023/10/09/video.mp4", 7, now.Add(time.Second))
	assert.False(t, ok, "mtime mismatch must be a miss")

	require.NoError(t, idx.Warm(context.Background(), root, 2))
	require.NoError(t, idx.Close())

	idx2, err := digest.Open(digest.Options{Dir: filepath.Join(root, localstore.IndexDirName), Shards: 4})
	require.NoError(t, err)
	defer func() { _ = idx2.Close() }()

	got, ok = idx2.Lookup("2023/10/09/video.mp4", 7, now)
	require.True(t, ok)
	assert.Equal(t, hexSum, got)
	assert.False(t, idx2.NeedsWarm())
}

func TestWarmFillsMissingEntries(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	indexDir := filepath.Join(root, localstore.IndexDirName)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "2023", "10", "09"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "2023", "10", "09", "a.mp4"), []byte("alpha"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "b.mp4"), []byte("beta"), 0o600))
	// The warm walk must not descend into the index itself.
	require.NoError(t, os.MkdirAll(filepath.Join(indexDir, "00"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(indexDir, "00", "db"), []byte("not an object"), 0o600))

	idx, err := digest.Open(digest.Options{Dir: indexDir, Shards: 2})
	require.NoError(t, err)
	defer func() { _ = idx.Close() }()
	require.True(t, idx.NeedsWarm())

	require.NoError(t, idx.Warm(context.Background(), root, 2))

	for key, want := range map[string]string{
		"2023/10/09/a.mp4": "alpha",
		"b.mp4":            "beta",
	} {
		fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(key)))
		require.NoError(t, err)
		sum := sha256.Sum256([]byte(want))
		got, ok := idx.Lookup(key, fi.Size(), fi.ModTime())
		require.True(t, ok, key)
		assert.Equal(t, hex.EncodeToString(sum[:]), got)
	}

	if _, ok := idx.Lookup(localstore.IndexDirName+"/00/db", 12, time.Now()); ok {
		t.Fatal("index directory file must not be warmed")
	}
}

func TestStartWarmsEmptyIndex(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.mp4"), []byte("alpha"), 0o600))
	indexDir := filepath.Join(root, localstore.IndexDirName)
	idx, err := digest.Open(digest.Options{Dir: indexDir, Shards: 2})
	require.NoError(t, err)
	require.True(t, idx.NeedsWarm())

	idx.Start(t.Context(), root, 2)
	defer func() { _ = idx.Close() }()

	fi, err := os.Stat(filepath.Join(root, "a.mp4"))
	require.NoError(t, err)
	sum := sha256.Sum256([]byte("alpha"))

	require.Eventually(t, func() bool {
		got, ok := idx.Lookup("a.mp4", fi.Size(), fi.ModTime())
		return ok && got == hex.EncodeToString(sum[:])
	}, 2*time.Second, 10*time.Millisecond)
}

func TestOpenLockedReturnsError(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), localstore.IndexDirName)
	first, err := digest.Open(digest.Options{Dir: dir, Shards: 2})
	require.NoError(t, err)
	defer func() { _ = first.Close() }()

	_, err = digest.Open(digest.Options{Dir: dir, Shards: 2})
	require.ErrorContains(t, err, "locked")
}

func TestWarmMarkerTracksShardCount(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	indexDir := filepath.Join(root, localstore.IndexDirName)
	idx, err := digest.Open(digest.Options{Dir: indexDir, Shards: 2})
	require.NoError(t, err)
	require.True(t, idx.NeedsWarm())
	require.NoError(t, idx.Warm(context.Background(), root, 1))
	require.NoError(t, idx.Close())

	idx2, err := digest.Open(digest.Options{Dir: indexDir, Shards: 2})
	require.NoError(t, err)
	assert.False(t, idx2.NeedsWarm())
	require.NoError(t, idx2.Close())

	idx3, err := digest.Open(digest.Options{Dir: indexDir, Shards: 3})
	require.NoError(t, err)
	assert.True(t, idx3.NeedsWarm(), "changing shard count must force a warm")
	require.NoError(t, idx3.Close())
}

func TestOpenRejectsBadShardCount(t *testing.T) {
	t.Parallel()

	_, err := digest.Open(digest.Options{Dir: t.TempDir(), Shards: 0})
	require.NoError(t, err)

	_, err = digest.Open(digest.Options{Dir: t.TempDir(), Shards: 1000})
	require.Error(t, err)
}
