package service_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/digest"
	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	localstore "github.com/xMlex/s3vault/internal/adapter/local"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/service"
)

type localCountingStore struct {
	*localstore.Store
	gets int
}

func (s *localCountingStore) Get(ctx context.Context, key string) (io.ReadCloser, domain.ObjectMeta, error) {
	s.gets++
	return s.Store.Get(ctx, key)
}

// TestFetchStatLocalIndexMissHashesWithoutMaterializing is the cold-index
// contract: a miss computes the real digest (valid data, never a stale entry)
// but still does not copy the object into a spool file.
func TestFetchStatLocalIndexMissHashesWithoutMaterializing(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	key := "2023/10/09/VID.mp4"
	full := filepath.Join(root, filepath.FromSlash(key))
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o700))
	plain := []byte("0123456789abcdef")
	require.NoError(t, os.WriteFile(full, plain, 0o600))

	st, err := localstore.New(config.LocalConfig{Dir: root})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	idx, err := digest.Open(digest.Options{Dir: filepath.Join(root, localstore.IndexDirName), Shards: 2})
	require.NoError(t, err)
	t.Cleanup(func() { _ = idx.Close() })
	st.WithDigestIndex(idx)

	counted := &localCountingStore{Store: st}
	f := service.NewFetch(counted, encrypt.Passthrough{})

	got, err := f.Stat(context.Background(), key)
	require.NoError(t, err)
	sum := sha256.Sum256(plain)
	assert.Equal(t, hex.EncodeToString(sum[:]), got.SHA256)
	assert.Equal(t, int64(len(plain)), got.Size)
	assert.Empty(t, got.Path)
	assert.Equal(t, 0, counted.gets, "a miss hashes in place, not by materializing")

	// The computed digest must now be persisted for the next HEAD.
	fi, err := os.Stat(full)
	require.NoError(t, err)
	cached, ok := idx.Lookup(key, fi.Size(), fi.ModTime())
	require.True(t, ok)
	assert.Equal(t, hex.EncodeToString(sum[:]), cached)
}

// TestFetchStatLocalDigestIndex proves the end-to-end HEAD path for a
// containerless mode=none object: the attached index supplies the digest, and
// Stat neither hashes nor materializes the body.
func TestFetchStatLocalDigestIndex(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	key := "2023/10/09/VID.mp4"
	full := filepath.Join(root, filepath.FromSlash(key))
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o700))
	plain := []byte("0123456789abcdef")
	require.NoError(t, os.WriteFile(full, plain, 0o600))

	st, err := localstore.New(config.LocalConfig{Dir: root})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	idx, err := digest.Open(digest.Options{Dir: filepath.Join(root, localstore.IndexDirName), Shards: 2})
	require.NoError(t, err)
	t.Cleanup(func() { _ = idx.Close() })

	fi, err := os.Stat(full)
	require.NoError(t, err)
	sum := sha256.Sum256(plain)
	hexSum := hex.EncodeToString(sum[:])
	idx.Store(key, fi.Size(), fi.ModTime(), hexSum)
	st.WithDigestIndex(idx)

	counted := &localCountingStore{Store: st}
	f := service.NewFetch(counted, encrypt.Passthrough{})

	got, err := f.Stat(context.Background(), key)
	require.NoError(t, err)
	assert.Equal(t, int64(len(plain)), got.Size)
	assert.Equal(t, hexSum, got.SHA256)
	assert.Empty(t, got.Path)
	assert.Equal(t, 0, counted.gets, "index hit must not materialize the object")
}
