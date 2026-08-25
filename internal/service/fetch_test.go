package service_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/service"
)

func TestFetchDownloadPlain(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	require.NoError(t, store.Put(context.Background(), "k", bytes.NewReader([]byte("hello")), domain.PutMeta{}))
	dest := filepath.Join(t.TempDir(), "out.log")
	f := service.NewFetch(store, encrypt.Passthrough{})
	require.NoError(t, f.Download(context.Background(), "k", dest, io.Discard))
	b, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(b))
}

func TestFetchDownloadUsesContainerThumbprint(t *testing.T) {
	t.Parallel()
	headerTP := "cccccccccccccccccccccccccccccccccccccccc"
	sum, err := container.SHA256FromHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	require.NoError(t, err)
	tp, err := container.ThumbprintFromHex(headerTP)
	require.NoError(t, err)
	hdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: 6,
		SHA256:        sum,
		Enc:           container.EncCommand,
		Provider:      "cryptopro",
		Thumbprint:    tp,
	})
	require.NoError(t, err)

	store := newMemStore()
	require.NoError(t, store.Put(context.Background(), "k", bytes.NewReader(append(hdr, []byte("cipher")...)), domain.PutMeta{}))

	dir := t.TempDir()
	script := filepath.Join(dir, "echo-tp.sh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s' \"$CRYPTOPRO_THUMBPRINT\"\n"), 0o700))
	enc, err := encrypt.NewCommand(config.CommandEnc{
		Encrypt:    []string{script},
		Decrypt:    []string{script},
		Thumbprint: "dddddddddddddddddddddddddddddddddddddddd",
	})
	require.NoError(t, err)

	dest := filepath.Join(t.TempDir(), "out")
	f := service.NewFetch(store, enc)
	require.NoError(t, f.Download(context.Background(), "k", dest, io.Discard))
	b, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, headerTP, string(b))
}

func TestFetchDownloadPrefersContainerThumbprintOverConfig(t *testing.T) {
	t.Parallel()
	headerTP := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfgTP := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sum, err := container.SHA256FromHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	require.NoError(t, err)
	tp, err := container.ThumbprintFromHex(headerTP)
	require.NoError(t, err)
	hdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: 1,
		SHA256:        sum,
		Enc:           container.EncCommand,
		Provider:      "cryptopro",
		Thumbprint:    tp,
	})
	require.NoError(t, err)

	store := newMemStore()
	require.NoError(t, store.Put(context.Background(), "k", bytes.NewReader(append(hdr, []byte("x")...)), domain.PutMeta{}))

	dir := t.TempDir()
	script := filepath.Join(dir, "echo-tp.sh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s' \"$CRYPTOPRO_THUMBPRINT\"\n"), 0o700))
	enc, err := encrypt.NewCommand(config.CommandEnc{
		Encrypt: []string{script}, Decrypt: []string{script}, Thumbprint: cfgTP,
	})
	require.NoError(t, err)

	dest := filepath.Join(t.TempDir(), "out")
	require.NoError(t, service.NewFetch(store, enc).Download(context.Background(), "k", dest, io.Discard))
	b, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, headerTP, string(b))
}
