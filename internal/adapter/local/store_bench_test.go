package localstore_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	localstore "github.com/xMlex/s3vault/internal/adapter/local"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/domain"
)

func benchStore(b *testing.B, objects int) *localstore.Store {
	b.Helper()

	st, err := localstore.New(config.LocalConfig{Dir: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	for i := range objects {
		key := fmt.Sprintf("d%02d/obj-%06d.bin", i%16, i)
		if err := st.Put(ctx, key, bytes.NewReader([]byte("x")), domain.PutMeta{}); err != nil {
			b.Fatal(err)
		}
	}
	return st
}

func BenchmarkPut(b *testing.B) {
	st := benchStore(b, 0)
	ctx := context.Background()
	payload := bytes.Repeat([]byte("x"), 4096)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()

	for b.Loop() {
		if err := st.Put(ctx, "k.bin", bytes.NewReader(payload), domain.PutMeta{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkList(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("objects=%d", n), func(b *testing.B) {
			st := benchStore(b, n)
			ctx := context.Background()
			b.ReportAllocs()
			for b.Loop() {
				page, err := st.List(ctx, domain.ListOptions{})
				if err != nil {
					b.Fatal(err)
				}
				if page.KeyCount == 0 {
					b.Fatal("empty page")
				}
			}
		})
	}
}

// BenchmarkListPaged walks every page of a 10k-object store, re-walking and
// re-sorting the whole tree per page (the documented linear cost).
func BenchmarkListPaged(b *testing.B) {
	st := benchStore(b, 10_000)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		var token string
		for {
			page, err := st.List(ctx, domain.ListOptions{MaxKeys: 1000, ContinuationToken: token})
			if err != nil {
				b.Fatal(err)
			}
			if !page.IsTruncated {
				break
			}
			token = page.NextContinuationToken
		}
	}
}
