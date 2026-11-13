package localstore

import (
	"bytes"
	"container/list"
	"context"
	"strings"
	"testing"

	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/domain"
)

// resetSHAMemo drops the in-memory digest memo, so each iteration sees the file
// as a process that has never hashed it. The persistent index, when attached,
// deliberately survives: that is what it is for.
func resetSHAMemo(s *Store) {
	s.shaMu.Lock()
	defer s.shaMu.Unlock()

	s.shaCache = make(map[string]shaEntry)
	s.shaOrder = list.New()
	s.shaElems = make(map[string]*list.Element)
}

// benchIndex is a DigestIndex that always answers. It isolates the cost of a
// cold Head with a warm persistent index from the cost of hashing the file.
type benchIndex struct{ sum string }

func (i benchIndex) Lookup(_ string, _ domain.FileVersion) (string, bool) {
	return i.sum, i.sum != ""
}

func (benchIndex) Store(string, domain.FileVersion, string) {}

func (benchIndex) Delete(string) {}

func benchContainerlessStore(b *testing.B, size int) *Store {
	b.Helper()

	st, err := New(config.LocalConfig{Dir: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}

	b.Cleanup(func() { _ = st.Close() })

	if err := st.Put(context.Background(), "k", bytes.NewReader(make([]byte, size)), domain.PutMeta{}); err != nil {
		b.Fatal(err)
	}

	return st
}

// BenchmarkHeadContainerless measures the documented cold-HEAD cost of a
// containerless object in the local backend. With no header to read a digest
// from and no index entry, Head hashes the whole file before it can answer.
func BenchmarkHeadContainerless(b *testing.B) {
	const size = 32 << 20

	ctx := context.Background()

	b.Run("cold-no-index", func(b *testing.B) {
		st := benchContainerlessStore(b, size)

		b.SetBytes(size)
		b.ReportAllocs()

		for b.Loop() {
			resetSHAMemo(st)

			if _, err := st.Head(ctx, "k"); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("cold-index-hit", func(b *testing.B) {
		st := benchContainerlessStore(b, size)
		st.WithDigestIndex(benchIndex{sum: strings.Repeat("a", 64)})

		b.ReportAllocs()

		for b.Loop() {
			resetSHAMemo(st)

			if _, err := st.Head(ctx, "k"); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("warm-memo", func(b *testing.B) {
		st := benchContainerlessStore(b, size)

		if _, err := st.Head(ctx, "k"); err != nil {
			b.Fatal(err)
		}

		b.ReportAllocs()

		for b.Loop() {
			if _, err := st.Head(ctx, "k"); err != nil {
				b.Fatal(err)
			}
		}
	})
}
