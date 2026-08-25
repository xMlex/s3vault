package encrypt

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/config"
)

func TestNativeRoundTripKeyfile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "kek")
	kek := make([]byte, 32)
	_, err := rand.Read(kek)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath, kek, 0o600))

	n, err := NewNative(config.NativeEnc{Wrap: "keyfile", KeyFile: keyPath, ChunkSize: 16})
	require.NoError(t, err)

	plain := bytes.Repeat([]byte("abcdefghijklmnop"), 8)
	var encBuf bytes.Buffer
	require.NoError(t, n.Encrypt(context.Background(), &encBuf, bytes.NewReader(plain)))
	assert.True(t, bytes.HasPrefix(encBuf.Bytes(), []byte(magicV1)))

	var dec bytes.Buffer
	require.NoError(t, n.Decrypt(context.Background(), &dec, bytes.NewReader(encBuf.Bytes())))
	assert.Equal(t, plain, dec.Bytes())
}

func TestNativeTruncatedCiphertext(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "kek")
	require.NoError(t, os.WriteFile(keyPath, bytes.Repeat([]byte{1}, 32), 0o600))
	n, err := NewNative(config.NativeEnc{Wrap: "keyfile", KeyFile: keyPath, ChunkSize: 32})
	require.NoError(t, err)

	var encBuf bytes.Buffer
	require.NoError(t, n.Encrypt(context.Background(), &encBuf, bytes.NewReader([]byte("hello world"))))
	trunc := encBuf.Bytes()[:len(encBuf.Bytes())-4]

	err = n.Decrypt(context.Background(), io.Discard, bytes.NewReader(trunc))
	require.Error(t, err)
}

func TestNativeRSARoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privPath := filepath.Join(dir, "priv.pem")
	pubPath := filepath.Join(dir, "pub.pem")
	require.NoError(t, os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}), 0o600))
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}), 0o600))

	n, err := NewNative(config.NativeEnc{Wrap: "rsa-oaep", PublicKeyPath: pubPath, PrivateKeyPath: privPath})
	require.NoError(t, err)
	var encBuf, dec bytes.Buffer
	require.NoError(t, n.Encrypt(context.Background(), &encBuf, bytes.NewReader([]byte("rsa payload"))))
	require.NoError(t, n.Decrypt(context.Background(), &dec, bytes.NewReader(encBuf.Bytes())))
	assert.Equal(t, "rsa payload", dec.String())
}

func TestCommandCatRoundTrip(t *testing.T) {
	t.Parallel()
	c, err := NewCommand(config.CommandEnc{Encrypt: []string{"cat"}, Decrypt: []string{"cat"}})
	require.NoError(t, err)
	var encBuf, dec bytes.Buffer
	require.NoError(t, c.Encrypt(context.Background(), &encBuf, bytes.NewReader([]byte("cmd"))))
	require.NoError(t, c.Decrypt(context.Background(), &dec, bytes.NewReader(encBuf.Bytes())))
	assert.Equal(t, "cmd", dec.String())
}
