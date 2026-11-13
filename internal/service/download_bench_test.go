package service_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/service"
)

func benchNativeEncryptor(b *testing.B, chunk int) *encrypt.Native {
	b.Helper()

	keyFile := filepath.Join(b.TempDir(), "kek")
	require.NoError(b, os.WriteFile(keyFile, bytes.Repeat([]byte{7}, 32), 0o600))

	n, err := encrypt.NewNative(config.NativeEnc{Wrap: "keyfile", KeyFile: keyFile, ChunkSize: chunk})
	require.NoError(b, err)

	return n
}

// BenchmarkFetchDownloadNative measures the client download path, which verifies
// the decrypted stream against the S3VCTR01 header (size + SHA-256) before the
// rename (problems.md D5).
func BenchmarkFetchDownloadNative(b *testing.B) {
	enc := benchNativeEncryptor(b, 64<<10)

	plain := make([]byte, 8<<20)
	for i := range plain {
		plain[i] = byte(i * 31) //nolint:gosec // benchmark payload pattern
	}

	var cipher bytes.Buffer
	require.NoError(b, enc.Encrypt(context.Background(), &cipher, bytes.NewReader(plain)))

	sum := sha256.Sum256(plain)
	hdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: int64(len(plain)),
		SHA256:        sum[:],
		Enc:           container.EncNative,
		Wrap:          container.WrapFromName("keyfile"),
	})
	require.NoError(b, err)

	store := newMemStore()
	require.NoError(b, store.Put(context.Background(), "k",
		io.MultiReader(bytes.NewReader(hdr), bytes.NewReader(cipher.Bytes())), domain.PutMeta{}))

	dest := filepath.Join(b.TempDir(), "out")
	f := service.NewFetch(store, enc)
	ctx := context.Background()

	b.SetBytes(int64(len(plain)))
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if err := f.Download(ctx, "k", dest, io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}
