package digest_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/digest"
	localstore "github.com/xMlex/s3vault/internal/adapter/local"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/domain"
)

func TestIndexPersistsAndValidatesStat(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	idx, err := digest.Open(digest.Options{Dir: filepath.Join(root, localstore.IndexDirName), Shards: 4})
	require.NoError(t, err)

	sum := sha256.Sum256([]byte("payload"))
	hexSum := hex.EncodeToString(sum[:])
	now := time.Now().UTC()
	version := domain.FileVersion{Size: 7, ModTime: now, ChangeTime: now, Inode: 42, Device: 7}
	idx.Store("2023/10/09/video.mp4", version, hexSum)

	got, ok := idx.Lookup("2023/10/09/video.mp4", version)
	require.True(t, ok)
	assert.Equal(t, hexSum, got)

	_, ok = idx.Lookup("2023/10/09/video.mp4", domain.FileVersion{Size: 8, ModTime: now, ChangeTime: now, Inode: 42, Device: 7})
	assert.False(t, ok, "size mismatch must be a miss")

	_, ok = idx.Lookup("2023/10/09/video.mp4", domain.FileVersion{Size: 7, ModTime: now.Add(time.Second), ChangeTime: now, Inode: 42, Device: 7})
	assert.False(t, ok, "mtime mismatch must be a miss")

	_, ok = idx.Lookup("2023/10/09/video.mp4", domain.FileVersion{Size: 7, ModTime: now, ChangeTime: now.Add(time.Second), Inode: 42, Device: 7})
	assert.False(t, ok, "ctime mismatch must be a miss")

	_, ok = idx.Lookup("2023/10/09/video.mp4", domain.FileVersion{Size: 7, ModTime: now, ChangeTime: now, Inode: 43, Device: 7})
	assert.False(t, ok, "inode mismatch must be a miss")

	require.NoError(t, idx.Warm(context.Background(), root, 2))
	require.NoError(t, idx.Close())

	idx2, err := digest.Open(digest.Options{Dir: filepath.Join(root, localstore.IndexDirName), Shards: 4})
	require.NoError(t, err)

	defer func() { _ = idx2.Close() }()

	got, ok = idx2.Lookup("2023/10/09/video.mp4", version)
	require.True(t, ok)
	assert.Equal(t, hexSum, got)
	assert.False(t, idx2.NeedsWarm())
}

// A platform without a change time stores a zero ChangeTime; that must
// round-trip as zero rather than as an arbitrary time far from the Unix epoch.
func TestIndexRoundTripsZeroChangeTime(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	idx, err := digest.Open(digest.Options{Dir: filepath.Join(root, localstore.IndexDirName), Shards: 2})
	require.NoError(t, err)

	defer func() { _ = idx.Close() }()

	sum := sha256.Sum256([]byte("payload"))
	hexSum := hex.EncodeToString(sum[:])
	version := domain.FileVersion{Size: 7, ModTime: time.Now().UTC()}
	idx.Store("win.bin", version, hexSum)

	got, ok := idx.Lookup("win.bin", version)
	require.True(t, ok)
	assert.Equal(t, hexSum, got)
}

// TestListUsesCachedDigestAndDoesNotHashMisses pins the List policy: a digest
// already known for the file version becomes the ETag, while a cold object
// keeps the synthetic validator and is never hashed (listing stays linear in
// object count, not bytes).
func TestListUsesCachedDigestAndDoesNotHashMisses(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.bin"), []byte("alpha"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "b.bin"), []byte("beta"), 0o600))

	st, err := localstore.New(config.LocalConfig{Dir: root})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	idx, err := digest.Open(digest.Options{Dir: filepath.Join(root, localstore.IndexDirName), Shards: 2})
	require.NoError(t, err)
	t.Cleanup(func() { _ = idx.Close() })
	st.WithDigestIndex(idx)

	// Cache a digest for a.bin only, as a previous HEAD or warm would.
	fiA, err := os.Stat(filepath.Join(root, "a.bin"))
	require.NoError(t, err)

	sumA := sha256.Sum256([]byte("alpha"))
	hexA := hex.EncodeToString(sumA[:])
	idx.Store("a.bin", localstore.FileVersionOf(fiA), hexA)

	page, err := st.List(context.Background(), domain.ListOptions{})
	require.NoError(t, err)
	require.Len(t, page.Contents, 2)

	etags := map[string]string{}
	for _, obj := range page.Contents {
		etags[obj.Key] = obj.ETag
	}

	assert.Equal(t, strconv.Quote(hexA), etags["a.bin"], "a cached digest must become the List ETag")

	sumB := sha256.Sum256([]byte("beta"))
	assert.NotEqual(t, strconv.Quote(hex.EncodeToString(sumB[:])), etags["b.bin"])
	assert.Regexp(t, `^"[0-9a-f]+-[0-9a-f]+"$`, etags["b.bin"], "a cold object keeps the synthetic validator")

	// A list must not hash cold objects, so b.bin stays out of the index.
	fiB, err := os.Stat(filepath.Join(root, "b.bin"))
	require.NoError(t, err)

	_, ok := idx.Lookup("b.bin", localstore.FileVersionOf(fiB))
	assert.False(t, ok, "List must not hash or populate the index on a miss")
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
		got, ok := idx.Lookup(key, localstore.FileVersionOf(fi))
		require.True(t, ok, key)
		assert.Equal(t, hex.EncodeToString(sum[:]), got)
	}

	if _, ok := idx.Lookup(localstore.IndexDirName+"/00/db", domain.FileVersion{Size: 12, ModTime: time.Now()}); ok {
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
		got, ok := idx.Lookup("a.mp4", localstore.FileVersionOf(fi))
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

// TestLocalStoreRehashesSameSizeSameMTimeOverwrite covers the gateway HEAD path:
// an external sync may replace the bytes while preserving size and mtime (rsync
// -t, cp -p, a tar restore), so the digest cache must also key on the inode
// change time. Without it HEAD keeps returning the previous file's SHA-256.
func TestLocalStoreRehashesSameSizeSameMTimeOverwrite(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	st, err := localstore.New(config.LocalConfig{Dir: root})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	idx, err := digest.Open(digest.Options{Dir: filepath.Join(root, localstore.IndexDirName), Shards: 2})
	require.NoError(t, err)
	t.Cleanup(func() { _ = idx.Close() })
	st.WithDigestIndex(idx)

	mtime := time.Unix(1_700_000_000, 0).UTC()
	p := filepath.Join(root, "k.bin")

	write := func(body string) {
		t.Helper()
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		require.NoError(t, os.Chtimes(p, mtime, mtime))
	}

	head := func(body string) {
		t.Helper()

		got, err := st.Head(context.Background(), "k.bin")
		require.NoError(t, err)

		sum := sha256.Sum256([]byte(body))
		assert.Equal(t, hex.EncodeToString(sum[:]), got.SHA256)
	}

	write("AAAA")
	head("AAAA")

	// In-place rewrite with the mtime restored: only ctime distinguishes it.
	write("BBBB")
	head("BBBB")

	// Atomic replacement through rename, mtime restored: the inode changes too.
	tmp := filepath.Join(root, ".tmp-k")
	require.NoError(t, os.WriteFile(tmp, []byte("CCCC"), 0o600))
	require.NoError(t, os.Chtimes(tmp, mtime, mtime))
	require.NoError(t, os.Rename(tmp, p))
	head("CCCC")
}
