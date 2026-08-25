package encrypt

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xMlex/s3vault/internal/config"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func nativeForBench(b *testing.B, chunk int) *Native {
	b.Helper()
	dir := b.TempDir()
	keyPath := filepath.Join(dir, "kek")
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(keyPath, kek, 0o600); err != nil {
		b.Fatal(err)
	}
	n, err := NewNative(config.NativeEnc{Wrap: "keyfile", KeyFile: keyPath, ChunkSize: chunk})
	if err != nil {
		b.Fatal(err)
	}
	return n
}

func BenchmarkNativeEncrypt(b *testing.B) {
	const size = 8 << 20
	n := nativeForBench(b, 65536)
	b.SetBytes(size)
	b.ReportAllocs()
	for b.Loop() {
		src := io.LimitReader(zeroReader{}, size)
		if err := n.Encrypt(context.Background(), io.Discard, src); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNativeDecrypt(b *testing.B) {
	const size = 8 << 20
	n := nativeForBench(b, 65536)
	pr, pw := io.Pipe()
	go func() {
		_ = pw.CloseWithError(n.Encrypt(context.Background(), pw, io.LimitReader(zeroReader{}, size)))
	}()
	cipher, err := io.ReadAll(pr)
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(size)
	b.ReportAllocs()
	for b.Loop() {
		if err := n.Decrypt(context.Background(), io.Discard, bytes.NewReader(cipher)); err != nil {
			b.Fatal(err)
		}
	}
}

func TestNativeEncryptHeapStaysNearChunk(t *testing.T) {
	const payload = 32 << 20
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "kek")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := NewNative(config.NativeEnc{Wrap: "keyfile", KeyFile: keyPath, ChunkSize: 65536})
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	if err := n.Encrypt(context.Background(), io.Discard, io.LimitReader(zeroReader{}, payload)); err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	delta := int64(after.HeapInuse) - int64(before.HeapInuse)
	if delta < 0 {
		delta = 0
	}
	const maxLive = 4 << 20
	if delta > maxLive {
		t.Fatalf("heap inuse grew by %d bytes after encrypting %d bytes (limit %d)", delta, payload, maxLive)
	}
}
