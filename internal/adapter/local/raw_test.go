package localstore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	metaBytes, err := os.ReadFile(filepath.Join(dir, "logs", "app.log.s3vault-meta"))
	require.NoError(t, err)
	require.Len(t, metaBytes, container.HeaderSize)
	assert.True(t, container.IsMagic(metaBytes))

	meta, err := st.Head(ctx, "logs/app.log")
	require.NoError(t, err)
	assert.Equal(t, int64(len(payload)), meta.Size)
	assert.Equal(t, hex.EncodeToString(sha256Sum(payload)), meta.SHA256)
	assert.Equal(t, int64(len(payload)), meta.ContentSize)
	assert.Equal(t, "none", meta.Encrypted)
	assert.Equal(t, container.FormatVersion, meta.FormatVersion)

	rc, getMeta, err := st.Get(ctx, "logs/app.log")
	require.NoError(t, err)
	got, err := io.ReadAll(rc)
	require.NoError(t, rc.Close())
	require.NoError(t, err)
	assert.Equal(t, payload, got)
	assert.Equal(t, meta.SHA256, getMeta.SHA256)

	page, err := st.List(ctx, domain.ListOptions{})
	require.NoError(t, err)
	require.Len(t, page.Contents, 1)
	assert.Equal(t, "logs/app.log", page.Contents[0].Key)
}

func TestRawLayoutIdentitySkipViaSidecar(t *testing.T) {
	t.Parallel()
	st, _ := newRawStore(t)
	ctx := context.Background()
	payload := []byte("dedup me")
	body := contained(t, payload, time.Now().UTC())
	require.NoError(t, st.Put(ctx, "k.bin", bytes.NewReader(body), domain.PutMeta{}))

	remote, err := identity.ResolveRemote(ctx, st, "k.bin")
	require.NoError(t, err)
	sum := hex.EncodeToString(sha256Sum(payload))
	assert.Equal(t, identity.ActionSkip, identity.Decide(sum, int64(len(payload)), remote, identity.OnChangeOverwrite))
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
	_, err = os.Stat(filepath.Join(dir, "plain.txt.s3vault-meta"))
	assert.True(t, os.IsNotExist(err), "no sidecar without container header")

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

func TestRawLayoutDeleteRemovesSidecar(t *testing.T) {
	t.Parallel()
	st, dir := newRawStore(t)
	ctx := context.Background()
	body := contained(t, []byte("x"), time.Now().UTC())
	require.NoError(t, st.Put(ctx, "a/b.log", bytes.NewReader(body), domain.PutMeta{}))
	require.NoError(t, st.Delete(ctx, "a/b.log"))

	_, err := os.Stat(filepath.Join(dir, "a", "b.log"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(dir, "a", "b.log.s3vault-meta"))
	assert.True(t, os.IsNotExist(err))
}

// Failed object Remove must not drop the sidecar first — otherwise plaintext
// remains without identity and ResolveRemote can no longer dedup.
func TestRawLayoutDeleteKeepsSidecarWhenObjectRemoveFails(t *testing.T) {
	t.Parallel()
	st, dir := newRawStore(t)
	ctx := context.Background()
	body := contained(t, []byte("keep-meta"), time.Now().UTC())
	require.NoError(t, st.Put(ctx, "stuck.log", bytes.NewReader(body), domain.PutMeta{}))

	obj := filepath.Join(dir, "stuck.log")
	meta := obj + ".s3vault-meta"
	require.NoError(t, os.Remove(obj))
	require.NoError(t, os.Mkdir(obj, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(obj, "blocker"), []byte("x"), 0o600))

	err := st.Delete(ctx, "stuck.log")
	require.Error(t, err)

	_, err = os.Stat(meta)
	require.NoError(t, err, "sidecar must survive a failed object delete")
}

func TestRawLayoutDeleteCleansOrphanSidecar(t *testing.T) {
	t.Parallel()
	st, dir := newRawStore(t)
	ctx := context.Background()
	body := contained(t, []byte("orphan"), time.Now().UTC())
	require.NoError(t, st.Put(ctx, "gone.log", bytes.NewReader(body), domain.PutMeta{}))

	obj := filepath.Join(dir, "gone.log")
	meta := obj + ".s3vault-meta"
	require.NoError(t, os.Remove(obj))

	require.NoError(t, st.Delete(ctx, "gone.log"))
	_, err := os.Stat(meta)
	assert.True(t, os.IsNotExist(err))
}

func TestRawLayoutMetaKeyReserved(t *testing.T) {
	t.Parallel()
	st, _ := newRawStore(t)
	_, err := st.Head(context.Background(), "a.log.s3vault-meta")
	require.ErrorIs(t, err, domain.ErrInvalidPath)
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
