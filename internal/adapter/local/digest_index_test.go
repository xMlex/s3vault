package localstore_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	localstore "github.com/xMlex/s3vault/internal/adapter/local"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/domain"
)

type fakeDigestIndex struct {
	mu      sync.Mutex
	sum     string
	hit     bool
	stored  map[string]string
	deleted []string
}

func (f *fakeDigestIndex) Lookup(string, int64, time.Time) (string, bool) {
	return f.sum, f.hit
}

func (f *fakeDigestIndex) Store(key string, _ int64, _ time.Time, sum string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stored == nil {
		f.stored = map[string]string{}
	}
	f.stored[key] = sum
}

func (f *fakeDigestIndex) Delete(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, key)
}

func TestDigestIndexHitSkipsHashing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "k"), []byte("payload"), 0o600))

	st, err := localstore.New(config.LocalConfig{Dir: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	const want = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	st.WithDigestIndex(&fakeDigestIndex{sum: want, hit: true})

	got, err := st.Head(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, want, got.SHA256)
}

func TestDigestIndexMissHashesAndStores(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	payload := []byte("payload")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "k"), payload, 0o600))

	st, err := localstore.New(config.LocalConfig{Dir: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	idx := &fakeDigestIndex{}
	st.WithDigestIndex(idx)

	got, err := st.Head(context.Background(), "k")
	require.NoError(t, err)

	sum := sha256.Sum256(payload)
	assert.Equal(t, hex.EncodeToString(sum[:]), got.SHA256)
	idx.mu.Lock()
	assert.Equal(t, got.SHA256, idx.stored["k"])
	idx.mu.Unlock()
}

func TestDigestIndexPutAndDelete(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	st, err := localstore.New(config.LocalConfig{Dir: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	idx := &fakeDigestIndex{}
	st.WithDigestIndex(idx)

	sum := strings.Repeat("b", 64)
	require.NoError(t, st.Put(context.Background(), "k", strings.NewReader("x"), domain.PutMeta{PlaintextSHA256: sum}))
	idx.mu.Lock()
	assert.Equal(t, sum, idx.stored["k"])
	idx.mu.Unlock()

	require.NoError(t, st.Delete(context.Background(), "k"))
	idx.mu.Lock()
	assert.Equal(t, []string{"k"}, idx.deleted)
	idx.mu.Unlock()
}

func TestDigestIndexClearsEntriesForMissingAndReplacedObjects(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	st, err := localstore.New(config.LocalConfig{Dir: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	idx := &fakeDigestIndex{}
	st.WithDigestIndex(idx)

	// A containerless Put stores an entry.
	sum := strings.Repeat("c", 64)
	require.NoError(t, st.Put(context.Background(), "k", strings.NewReader("raw"), domain.PutMeta{PlaintextSHA256: sum}))
	idx.mu.Lock()
	require.Equal(t, sum, idx.stored["k"])
	idx.mu.Unlock()

	// Replacing it with a container object must drop the old raw digest.
	require.NoError(t, st.Put(context.Background(), "k", strings.NewReader("container"), domain.PutMeta{}))
	idx.mu.Lock()
	assert.Contains(t, idx.deleted, "k")
	idx.mu.Unlock()

	// HEAD of a missing key also prunes a stale entry.
	deletedBefore := len(idx.deleted)
	_, err = st.Head(context.Background(), "gone")
	require.NoError(t, err)
	idx.mu.Lock()
	assert.Len(t, idx.deleted, deletedBefore+1)
	idx.mu.Unlock()
}

func TestIndexDirectoryIsReserved(t *testing.T) {
	t.Parallel()

	st, err := localstore.New(config.LocalConfig{Dir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	for _, key := range []string{localstore.IndexDirName, localstore.IndexDirName + "/00/db"} {
		_, err := st.Head(context.Background(), key)
		require.ErrorIs(t, err, domain.ErrInvalidPath)
		require.ErrorIs(t, st.Put(context.Background(), key, strings.NewReader("x"), domain.PutMeta{}), domain.ErrInvalidPath)
	}

	require.NoError(t, os.MkdirAll(filepath.Join(st.Dir(), localstore.IndexDirName, "00"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(st.Dir(), localstore.IndexDirName, "00", "db"), []byte("x"), 0o600))

	page, err := st.List(context.Background(), domain.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, page.Contents)
}
