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
	"strings"
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
	assert.Equal(t, hex.EncodeToString(sha256Sum(payload)), meta.SHA256)

	rc, getMeta, err := st.Get(ctx, "logs/app.log")
	require.NoError(t, err)
	got, err := io.ReadAll(rc)
	require.NoError(t, rc.Close())
	require.NoError(t, err)
	assert.Equal(t, payload, got)
	assert.Equal(t, hex.EncodeToString(sha256Sum(payload)), getMeta.SHA256)

	page, err := st.List(ctx, domain.ListOptions{})
	require.NoError(t, err)
	require.Len(t, page.Contents, 1)
	assert.Equal(t, "logs/app.log", page.Contents[0].Key)
}

// raw layout has no container header; the store derives plaintext SHA-256 from
// the file itself (memoized in memory) so GET/HEAD can expose identity.
func TestRawLayoutHeadReportsSHA256(t *testing.T) {
	t.Parallel()
	st, _ := newRawStore(t)
	ctx := context.Background()
	payload := []byte("dedup me")
	body := contained(t, payload, time.Now().UTC())
	require.NoError(t, st.Put(ctx, "k.bin", bytes.NewReader(body), domain.PutMeta{}))

	want := hex.EncodeToString(sha256Sum(payload))
	remote, err := identity.ResolveRemote(ctx, st, "k.bin")
	require.NoError(t, err)
	assert.Equal(t, want, remote.SHA256)
}

// The memo is keyed by size+mtime, so rewriting an object re-derives the digest.
func TestRawLayoutSHACacheInvalidatesOnRewrite(t *testing.T) {
	t.Parallel()
	st, _ := newRawStore(t)
	ctx := context.Background()
	require.NoError(t, st.Put(ctx, "k.bin", strings.NewReader("first"), domain.PutMeta{}))
	first, err := st.Head(ctx, "k.bin")
	require.NoError(t, err)
	require.NotEmpty(t, first.SHA256)

	require.NoError(t, st.Put(ctx, "k.bin", strings.NewReader("second-longer"), domain.PutMeta{}))
	second, err := st.Head(ctx, "k.bin")
	require.NoError(t, err)
	assert.NotEqual(t, first.SHA256, second.SHA256)
	assert.Equal(t, hex.EncodeToString(sha256Sum([]byte("second-longer"))), second.SHA256)
}

// The memo is consulted before reading: rewrite the bytes in place but restore
// size and mtime, and the cached digest is served instead of a re-read.
func TestRawLayoutSHACacheHitAvoidsReread(t *testing.T) {
	t.Parallel()
	st, dir := newRawStore(t)
	ctx := context.Background()
	payload := []byte("first")
	require.NoError(t, st.Put(ctx, "k.bin", bytes.NewReader(payload), domain.PutMeta{}))
	fi, err := os.Stat(filepath.Join(dir, "k.bin"))
	require.NoError(t, err)

	first, err := st.Head(ctx, "k.bin")
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(sha256Sum(payload)), first.SHA256)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "k.bin"), []byte("other"), 0o600))
	require.NoError(t, os.Chtimes(filepath.Join(dir, "k.bin"), fi.ModTime(), fi.ModTime()))

	second, err := st.Head(ctx, "k.bin")
	require.NoError(t, err)
	assert.Equal(t, first.SHA256, second.SHA256)
}

// Archive keeps the raw fast path: it never hashes the local file, so Decide
// sees an empty local digest and re-uploads even though the store reports one.
func TestRawLayoutArchivePassesNoLocalDigest(t *testing.T) {
	t.Parallel()
	st, _ := newRawStore(t)
	ctx := context.Background()
	payload := []byte("dedup me")
	body := contained(t, payload, time.Now().UTC())
	require.NoError(t, st.Put(ctx, "k.bin", bytes.NewReader(body), domain.PutMeta{}))

	remote, err := identity.ResolveRemote(ctx, st, "k.bin")
	require.NoError(t, err)
	assert.Equal(t,
		identity.ActionUpload,
		identity.Decide("", int64(len(payload)), remote, identity.OnChangeOverwrite))
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
	assert.Equal(t, hex.EncodeToString(sha256Sum(payload)), meta.SHA256)
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
