package cache

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/xMlex/s3vault/internal/port"
)

func newBenchDisk(b *testing.B, opt Options) *Disk {
	b.Helper()
	opt.Dir = b.TempDir()
	d, err := New(opt)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = d.Close() })
	return d
}

func benchFill(payload []byte) func(io.Writer) error {
	return func(w io.Writer) error {
		_, err := w.Write(payload)
		return err
	}
}

func BenchmarkDiskGet(b *testing.B) {
	d := newBenchDisk(b, Options{TTL: time.Hour, MaxBytes: 1 << 30})
	id := ID("bench", "get", "fp")
	payload := make([]byte, 64<<10)
	if _, err := d.Populate(context.Background(), id, port.EntryMeta{}, benchFill(payload)); err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		_, hit, err := d.Get(ctx, id)
		if err != nil {
			b.Fatal(err)
		}
		if !hit {
			b.Fatal("expected hit")
		}
	}
}

func BenchmarkDiskGetMiss(b *testing.B) {
	d := newBenchDisk(b, Options{TTL: time.Hour})
	id := ID("bench", "miss", "fp")
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		_, hit, err := d.Get(ctx, id)
		if err != nil {
			b.Fatal(err)
		}
		if hit {
			b.Fatal("expected miss")
		}
	}
}

func BenchmarkDiskGetAtimeFlush(b *testing.B) {
	d := newBenchDisk(b, Options{TTL: time.Hour, MaxBytes: 1 << 30})
	id := ID("bench", "atime", "fp")
	if _, err := d.Populate(context.Background(), id, port.EntryMeta{}, benchFill([]byte("x"))); err != nil {
		b.Fatal(err)
	}
	_, metaRel, _, _, err := d.rel(id)
	if err != nil {
		b.Fatal(err)
	}
	key := string(id)
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		sc, err := d.readMeta(metaRel)
		if err != nil {
			b.Fatal(err)
		}
		sc.ATime = time.Time{}
		if err := d.writeMeta(metaRel, sc); err != nil {
			b.Fatal(err)
		}
		d.touch(key, time.Time{}) // keep index in sync with forced-stale sidecar
		b.StartTimer()

		_, hit, err := d.Get(ctx, id)
		if err != nil {
			b.Fatal(err)
		}
		if !hit {
			b.Fatal("expected hit")
		}
	}
}

func BenchmarkDiskGetParallel(b *testing.B) {
	d := newBenchDisk(b, Options{TTL: time.Hour, MaxBytes: 1 << 30})
	id := ID("bench", "get-par", "fp")
	if _, err := d.Populate(context.Background(), id, port.EntryMeta{}, benchFill(make([]byte, 64<<10))); err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, hit, err := d.Get(ctx, id)
			if err != nil {
				b.Error(err)
				return
			}
			if !hit {
				b.Error("expected hit")
				return
			}
		}
	})
}

func BenchmarkDiskPopulate(b *testing.B) {
	for _, size := range []int{64, 4 << 10, 64 << 10, 1 << 20} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			d := newBenchDisk(b, Options{TTL: time.Hour})
			payload := make([]byte, size)
			fill := benchFill(payload)
			ctx := context.Background()
			b.SetBytes(int64(size))
			b.ReportAllocs()
			var n int
			for b.Loop() {
				id := ID("bench", "pop-"+strconv.Itoa(n), "fp")
				n++
				if _, err := d.Populate(ctx, id, port.EntryMeta{}, fill); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDiskPopulateHit(b *testing.B) {
	d := newBenchDisk(b, Options{TTL: time.Hour, MaxBytes: 1 << 30})
	id := ID("bench", "pop-hit", "fp")
	payload := make([]byte, 64<<10)
	fill := benchFill(payload)
	if _, err := d.Populate(context.Background(), id, port.EntryMeta{}, fill); err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := d.Populate(ctx, id, port.EntryMeta{}, fill); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDiskPopulateParallel(b *testing.B) {
	d := newBenchDisk(b, Options{TTL: time.Hour, MaxBytes: 1 << 30})
	id := ID("bench", "pop-par", "fp")
	payload := make([]byte, 64<<10)
	fill := benchFill(payload)
	ctx := context.Background()

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := d.Populate(ctx, id, port.EntryMeta{}, fill); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkDiskEvict(b *testing.B) {
	const entrySize = 1024
	const keep = 64
	d := newBenchDisk(b, Options{TTL: time.Hour, MaxBytes: keep * entrySize})
	payload := make([]byte, entrySize)
	fill := benchFill(payload)
	ctx := context.Background()
	for i := range keep {
		id := ID("bench", "evict-seed-"+strconv.Itoa(i), "fp")
		if _, err := d.Populate(ctx, id, port.EntryMeta{}, fill); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	var n int
	for b.Loop() {
		id := ID("bench", "evict-"+strconv.Itoa(n), "fp")
		n++
		if _, err := d.Populate(ctx, id, port.EntryMeta{}, fill); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDiskUsage(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			d := newBenchDisk(b, Options{TTL: time.Hour})
			payload := []byte("x")
			fill := benchFill(payload)
			ctx := context.Background()
			for i := range n {
				id := ID("bench", "usage-"+strconv.Itoa(i), "fp")
				if _, err := d.Populate(ctx, id, port.EntryMeta{}, fill); err != nil {
					b.Fatal(err)
				}
			}

			b.ReportAllocs()
			for b.Loop() {
				if _, err := d.Usage(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
