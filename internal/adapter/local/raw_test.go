package localstore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	localstore "github.com/xMlex/s3vault/internal/adapter/local"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/identity"
)

func newRawStore(t *testing.T) (*localstore.Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "objects")
	st, err := localstore.New(config.LocalConfig{Dir: dir, Layout: config.LocalLayoutRaw})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	assert.Equal(t, config.LocalLayoutRaw, st.Layout())
	return st, dir
}

func contained(t *testing.T, payload []byte, mtime time.Time) []byte {
	t.Helper()
	sum := sha256.Sum256(payload)
	hdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: int64(len(payload)),
		SHA256:        sum[:],
		Enc:           container.EncNone,
		SourceMTime:   mtime,
	})
	require.NoError(t, err)
	return append(hdr, payload...)
}

func TestRawLayoutStripsContainerToCleanFile(t *testing.T) {
	t.Parallel()
	st, dir := newRawStore(t)
	ctx := context.Background()
	payload := []byte("clean plaintext\n")
	body := contained(t, payload, time.Unix(1_700_000_000, 0).UTC())

	require.NoError(t, st.Put(ctx, "logs/app.log", bytes.NewReader(body), domain.PutMeta{}))

	raw, err := os.ReadFile(filepath.Join(dir, "logs", "app.log"))
	require.NoError(t, err)
	assert.Equal(t, payload, raw, "object file must be plaintext only")

	meta, err := st.Head(ctx, "logs/app.log")
	require.NoError(t, err)
	assert.Equal(t, int64(len(payload)), meta.Size)
	assert.Empty(t, meta.SHA256)

	rc, getMeta, err := st.Get(ctx, "logs/app.log")
	require.NoError(t, err)
	got, err := io.ReadAll(rc)
	require.NoError(t, rc.Close())
	require.NoError(t, err)
	assert.Equal(t, payload, got)
	assert.Empty(t, getMeta.SHA256)

	page, err := st.List(ctx, domain.ListOptions{})
	require.NoError(t, err)
	require.Len(t, page.Contents, 1)
	assert.Equal(t, "logs/app.log", page.Contents[0].Key)
}

func TestRawLayoutNoContentHashSkip(t *testing.T) {
	t.Parallel()
	st, _ := newRawStore(t)
	ctx := context.Background()
	payload := []byte("dedup me")
	body := contained(t, payload, time.Now().UTC())
	require.NoError(t, st.Put(ctx, "k.bin", bytes.NewReader(body), domain.PutMeta{}))

	remote, err := identity.ResolveRemote(ctx, st, "k.bin")
	require.NoError(t, err)
	sum := hex.EncodeToString(sha256Sum(payload))
	assert.Equal(t, identity.ActionUpload, identity.Decide(sum, int64(len(payload)), remote, identity.OnChangeOverwrite),
		"raw layout has no remote SHA-256 for skip")
}

func TestRawLayoutPassthroughWithoutContainer(t *testing.T) {
	t.Parallel()
	st, dir := newRawStore(t)
	ctx := context.Background()
	payload := []byte("already clean")
	require.NoError(t, st.Put(ctx, "plain.txt", bytes.NewReader(payload), domain.PutMeta{}))

	raw, err := os.ReadFile(filepath.Join(dir, "plain.txt"))
	require.NoError(t, err)
	assert.Equal(t, payload, raw)

	meta, err := st.Head(ctx, "plain.txt")
	require.NoError(t, err)
	assert.Empty(t, meta.SHA256)
}

func TestRawLayoutRejectsEncryptedContainer(t *testing.T) {
	t.Parallel()
	st, _ := newRawStore(t)
	sum := sha256.Sum256([]byte("x"))
	hdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: 1,
		SHA256:        sum[:],
		Enc:           container.EncNative,
		Wrap:          container.WrapKEK,
	})
	require.NoError(t, err)
	body := append(hdr, []byte("x")...)
	err = st.Put(context.Background(), "secret.bin", bytes.NewReader(body), domain.PutMeta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "layout=raw")
}

// Magic matches but the header is corrupt → raw Put must fail, not store it.
func TestRawLayoutRejectsCorruptHeader(t *testing.T) {
	t.Parallel()
	st, _ := newRawStore(t)
	bad := make([]byte, container.HeaderSize)
	copy(bad, container.Magic)
	bad = append(bad, 'x')

	err := st.Put(context.Background(), "bad.bin", bytes.NewReader(bad), domain.PutMeta{})
	require.ErrorIs(t, err, container.ErrCorruptHeader)
}

var errBoom = errors.New("boom")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errBoom }

func TestRawLayoutPutReadError(t *testing.T) {
	t.Parallel()
	st, _ := newRawStore(t)
	err := st.Put(context.Background(), "boom.bin", failingReader{}, domain.PutMeta{})
	require.ErrorIs(t, err, errBoom)
}

func TestRawLayoutDelete(t *testing.T) {
	t.Parallel()
	st, dir := newRawStore(t)
	ctx := context.Background()
	require.NoError(t, st.Put(ctx, "a/b.log", bytes.NewReader([]byte("x")), domain.PutMeta{}))
	require.NoError(t, st.Delete(ctx, "a/b.log"))

	_, err := os.Stat(filepath.Join(dir, "a", "b.log"))
	assert.True(t, os.IsNotExist(err))
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
