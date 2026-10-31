package service_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/service"
)

// benchObject stores a container-framed object of size bytes and returns a
// backend that reads it. It is the baseline these benchmarks measure: nothing
// here is tuned per run.
func benchObject(b *testing.B, size int) *memStore {
	b.Helper()

	plain := make([]byte, size)
	sum := sha256.Sum256(plain)

	hdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: int64(size),
		SHA256:        sum[:],
		Enc:           container.EncNone,
	})
	if err != nil {
		b.Fatal(err)
	}

	store := newMemStore()
	if err := store.Put(context.Background(), "k",
		io.MultiReader(bytes.NewReader(hdr), bytes.NewReader(plain)), domain.PutMeta{}); err != nil {
		b.Fatal(err)
	}

	return store
}

func BenchmarkFetchStat(b *testing.B) {
	const size = 5 << 20

	store := benchObject(b, size)
	f := service.NewFetch(store, encrypt.Passthrough{})
	ctx := context.Background()

	b.SetBytes(size)
	b.ReportAllocs()

	for b.Loop() {
		if _, err := f.Stat(ctx, "k"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFetchOpenRange1KiB(b *testing.B) {
	const size = 8 << 20

	store := benchObject(b, size)
	f := service.NewFetch(store, encrypt.Passthrough{})
	ctx := context.Background()
	buf := make([]byte, 1024)

	b.ReportAllocs()

	for b.Loop() {
		rc, _, err := f.Open(ctx, "k")
		if err != nil {
			b.Fatal(err)
		}

		if _, err := rc.Seek(size/2, io.SeekStart); err != nil {
			b.Fatal(err)
		}

		if _, err := io.ReadFull(rc, buf); err != nil {
			b.Fatal(err)
		}

		_ = rc.Close()
	}
}

func BenchmarkFetchOpenAll(b *testing.B) {
	const size = 8 << 20

	store := benchObject(b, size)
	f := service.NewFetch(store, encrypt.Passthrough{})
	ctx := context.Background()

	b.SetBytes(size)
	b.ReportAllocs()

	for b.Loop() {
		rc, _, err := f.Open(ctx, "k")
		if err != nil {
			b.Fatal(err)
		}

		if _, err := io.Copy(io.Discard, rc); err != nil {
			b.Fatal(err)
		}

		_ = rc.Close()
	}
}
