package service_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"testing"
	"time"

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

// BenchmarkFetchStatCostByObjectShape contrasts the two HEAD shapes. A framed
// object answers from its 128-byte S3VCTR01 header; a legacy containerless
// object that declares no size makes Fetch.Stat materialize and decrypt the
// whole object just to learn the plaintext length (the documented fallback).
func BenchmarkFetchStatCostByObjectShape(b *testing.B) {
	const size = 16 << 20

	ctx := context.Background()

	b.Run("container", func(b *testing.B) {
		store := benchObject(b, size)
		f := service.NewFetch(store, encrypt.Passthrough{})

		b.ReportAllocs()

		for b.Loop() {
			if _, err := f.Stat(ctx, "k"); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("legacy-containerless", func(b *testing.B) {
		store := newMemStore()
		if err := store.Put(ctx, "k", bytes.NewReader(make([]byte, size)), domain.PutMeta{}); err != nil {
			b.Fatal(err)
		}

		f := service.NewFetch(store, encrypt.Passthrough{})

		b.SetBytes(size)
		b.ReportAllocs()

		for b.Loop() {
			if _, err := f.Stat(ctx, "k"); err != nil {
				b.Fatal(err)
			}
		}
	})

	// With a validator present the learned size is memoized: only the first HEAD
	// materializes, the rest answer from metadata. The backend reports an ETag
	// for every real object; the store above deliberately has none, which is why
	// its loop measures the uncached cost.
	b.Run("legacy-containerless-versioned", func(b *testing.B) {
		store := newMemStore()
		if err := store.Put(ctx, "k", bytes.NewReader(make([]byte, size)), domain.PutMeta{}); err != nil {
			b.Fatal(err)
		}

		store.mu.Lock()
		meta := store.meta["k"]
		meta.ETag = `"v1"`
		meta.LastModified = time.Unix(1700000000, 0)
		store.meta["k"] = meta
		store.mu.Unlock()

		f := service.NewFetch(store, encrypt.Passthrough{})
		if _, err := f.Stat(ctx, "k"); err != nil {
			b.Fatal(err)
		}

		b.ReportAllocs()

		for b.Loop() {
			if _, err := f.Stat(ctx, "k"); err != nil {
				b.Fatal(err)
			}
		}
	})
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
