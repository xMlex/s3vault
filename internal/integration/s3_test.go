//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	s3store "github.com/xMlex/s3vault/internal/adapter/s3"
	"github.com/xMlex/s3vault/internal/adapter/scanner"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/identity"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/s3test"
	"github.com/xMlex/s3vault/internal/service"
)

func TestS3PutHeadGetSkip(t *testing.T) {
	ctx := context.Background()
	store, prefix := newStore(t)
	key := prefix + "hello.txt"
	t.Cleanup(func() { _ = store.Delete(context.Background(), key) })

	body := []byte("s3vault integration payload")
	require.NoError(t, store.Put(ctx, key, bytes.NewReader(body), domain.PutMeta{}))

	meta, err := store.Head(ctx, key)
	require.NoError(t, err)
	require.True(t, meta.Exists)
	assert.Equal(t, int64(len(body)), meta.Size)

	rc, _, err := store.Get(ctx, key)
	require.NoError(t, err)
	got, err := io.ReadAll(rc)
	require.NoError(t, rc.Close())
	require.NoError(t, err)
	assert.Equal(t, body, got)

	missing, err := store.Head(ctx, prefix+"does-not-exist")
	require.NoError(t, err)
	assert.False(t, missing.Exists)
}

func TestArchiveUploadThenSkip(t *testing.T) {
	ctx := context.Background()
	store, prefix := newStore(t)
	root := t.TempDir()
	p := filepath.Join(root, "old.log")
	payload := []byte("archive-me")
	require.NoError(t, os.WriteFile(p, payload, 0o600))
	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(p, old, old))

	key := prefix + "old.log"
	t.Cleanup(func() { _ = store.Delete(context.Background(), key) })

	svc := service.NewArchive(
		scanner.New(scanner.Options{}),
		keying.Mapper{Prefix: stringsTrimSlash(prefix)},
		store,
		encrypt.Passthrough{},
		nil,
	)
	opts := service.ArchiveOptions{
		Root:      root,
		OlderThan: time.Hour,
		Workers:   2,
		OnChange:  identity.OnChangeOverwrite,
	}

	st, err := svc.Run(ctx, opts)
	require.NoError(t, err)
	assert.Equal(t, 1, st.Uploaded)
	assert.Equal(t, 0, st.Skipped)

	st, err = svc.Run(ctx, opts)
	require.NoError(t, err)
	assert.Equal(t, 0, st.Uploaded)
	assert.Equal(t, 1, st.Skipped)

	dest := filepath.Join(t.TempDir(), "out.log")
	require.NoError(t, service.NewFetch(store, encrypt.Passthrough{}).Download(ctx, key, dest, nil))
	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestEncryptedUploadDownload(t *testing.T) {
	ctx := context.Background()
	store, prefix := newStore(t)
	root := t.TempDir()
	p := filepath.Join(root, "secret.log")
	payload := []byte("top secret line")
	require.NoError(t, os.WriteFile(p, payload, 0o600))
	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(p, old, old))

	kekPath := filepath.Join(t.TempDir(), "kek")
	kek := make([]byte, 32)
	_, err := rand.Read(kek)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(kekPath, kek, 0o600))
	enc, err := encrypt.NewNative(config.NativeEnc{Wrap: "keyfile", KeyFile: kekPath, ChunkSize: 64})
	require.NoError(t, err)

	key := prefix + "secret.log"
	t.Cleanup(func() { _ = store.Delete(context.Background(), key) })

	svc := service.NewArchive(
		scanner.New(scanner.Options{}),
		keying.Mapper{Prefix: stringsTrimSlash(prefix)},
		store,
		enc,
		nil,
	)
	st, err := svc.Run(ctx, service.ArchiveOptions{
		Root:      root,
		OlderThan: time.Hour,
		Workers:   1,
		OnChange:  identity.OnChangeOverwrite,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, st.Uploaded)

	dest := filepath.Join(t.TempDir(), "plain.log")
	require.NoError(t, service.NewFetch(store, enc).Download(ctx, key, dest, nil))
	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func newStore(t *testing.T) (*s3store.Store, string) {
	t.Helper()
	cfg := s3test.ConfigFromEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	store, err := s3store.New(ctx, cfg)
	require.NoError(t, err)

	var b [4]byte
	_, _ = rand.Read(b[:])
	prefix := "s3vault-it/" + hex.EncodeToString(b[:]) + "/"
	return store, prefix
}

func stringsTrimSlash(s string) string {
	if len(s) > 0 && s[len(s)-1] == '/' {
		return s[:len(s)-1]
	}
	return s
}
