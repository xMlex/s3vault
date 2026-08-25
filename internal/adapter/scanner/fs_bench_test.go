package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func benchTree(b *testing.B, files, dirs int) string {
	b.Helper()
	root := b.TempDir()
	if dirs < 1 {
		dirs = 1
	}
	old := time.Now().Add(-48 * time.Hour)
	for i := range dirs {
		if err := os.MkdirAll(filepath.Join(root, fmt.Sprintf("d%d", i)), 0o700); err != nil {
			b.Fatal(err)
		}
	}
	for i := range files {
		dir := filepath.Join(root, fmt.Sprintf("d%d", i%dirs))
		path := filepath.Join(dir, fmt.Sprintf("f%d.log", i))
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			b.Fatal(err)
		}
		if err := os.Chtimes(path, old, old); err != nil {
			b.Fatal(err)
		}
	}
	return root
}

func BenchmarkFSStat(b *testing.B) {
	root := b.TempDir()
	file := filepath.Join(root, "a.log")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		b.Fatal(err)
	}
	s := New(Options{Logger: slog.New(slog.DiscardHandler)})

	b.ReportAllocs()
	for b.Loop() {
		if _, err := s.Stat(root, file); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFSScan(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("files=%d", n), func(b *testing.B) {
			root := benchTree(b, n, 10)
			s := New(Options{Logger: slog.New(slog.DiscardHandler)})
			ctx := context.Background()

			b.ReportAllocs()
			for b.Loop() {
				var count int
				for _, err := range s.Scan(ctx, root, time.Hour) {
					if err != nil {
						b.Fatal(err)
					}
					count++
				}
				if count != n {
					b.Fatalf("got %d files, want %d", count, n)
				}
			}
		})
	}
}

func BenchmarkFSScanSkipRecent(b *testing.B) {
	const n = 1_000
	root := benchTree(b, n, 10)
	// Half recent → filtered out by olderThan.
	recent := time.Now().Add(-time.Minute)
	for i := 0; i < n/2; i++ {
		path := filepath.Join(root, fmt.Sprintf("d%d", i%10), fmt.Sprintf("f%d.log", i))
		if err := os.Chtimes(path, recent, recent); err != nil {
			b.Fatal(err)
		}
	}
	s := New(Options{Logger: slog.New(slog.DiscardHandler)})
	ctx := context.Background()
	want := n / 2

	b.ReportAllocs()
	for b.Loop() {
		var count int
		for _, err := range s.Scan(ctx, root, time.Hour) {
			if err != nil {
				b.Fatal(err)
			}
			count++
		}
		if count != want {
			b.Fatalf("got %d files, want %d", count, want)
		}
	}
}
