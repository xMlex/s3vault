package identity_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/identity"
)

// latencyStore charges a fixed round-trip time for every backend call, which is
// what a HEAD through a real S3 hop costs. It exists only to expose how many
// round trips a code path spends: at rtt=0 the measurement is the code itself.
type latencyStore struct {
	rtt  time.Duration
	meta domain.ObjectMeta
	body []byte
}

func (s *latencyStore) wait(ctx context.Context) error {
	if s.rtt <= 0 {
		return ctx.Err()
	}

	t := time.NewTimer(s.rtt)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (s *latencyStore) Head(ctx context.Context, _ string) (domain.ObjectMeta, error) {
	if err := s.wait(ctx); err != nil {
		return domain.ObjectMeta{}, err
	}

	return s.meta, nil
}

func (s *latencyStore) GetRange(ctx context.Context, _ string, start, end int64) (io.ReadCloser, domain.ObjectMeta, error) {
	if err := s.wait(ctx); err != nil {
		return nil, domain.ObjectMeta{}, err
	}

	to := min(end+1, int64(len(s.body)))

	return io.NopCloser(bytes.NewReader(s.body[start:to])), s.meta, nil
}

func benchLatencyStore(b *testing.B, rtt time.Duration) *latencyStore {
	b.Helper()

	plain := make([]byte, 1<<20)
	sum := sha256.Sum256(plain)

	hdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: int64(len(plain)),
		SHA256:        sum[:],
		Enc:           container.EncNone,
	})
	if err != nil {
		b.Fatal(err)
	}

	body := make([]byte, 0, len(hdr)+len(plain))
	body = append(body, hdr...)
	body = append(body, plain...)

	return &latencyStore{
		rtt:  rtt,
		meta: domain.ObjectMeta{Key: "k", Exists: true, Size: int64(len(body))},
		body: body,
	}
}

// BenchmarkResolveRemoteRoundTrips measures what one HEAD through the facade
// costs in backend round trips. ResolveRemote issues HeadObject and then a
// 128-byte Range GET, so the request pays two RTTs before the facade can answer.
func BenchmarkResolveRemoteRoundTrips(b *testing.B) {
	for _, rtt := range []time.Duration{0, 2 * time.Millisecond, 10 * time.Millisecond} {
		b.Run(fmt.Sprintf("rtt=%s", rtt), func(b *testing.B) {
			store := benchLatencyStore(b, rtt)
			ctx := context.Background()

			b.ReportAllocs()

			for b.Loop() {
				if _, err := identity.ResolveRemote(ctx, store, "k"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkResolveRemoteOneRoundTrip is the floor a single Range GET could
// reach if the 128-byte header alone answered the identity: one backend call
// instead of two.
func BenchmarkResolveRemoteOneRoundTrip(b *testing.B) {
	for _, rtt := range []time.Duration{0, 2 * time.Millisecond, 10 * time.Millisecond} {
		b.Run(fmt.Sprintf("rtt=%s", rtt), func(b *testing.B) {
			store := benchLatencyStore(b, rtt)
			ctx := context.Background()
			buf := make([]byte, container.HeaderSize)

			b.ReportAllocs()

			for b.Loop() {
				body, _, err := store.GetRange(ctx, "k", 0, int64(container.HeaderSize-1))
				if err != nil {
					b.Fatal(err)
				}

				if _, err := io.ReadFull(body, buf); err != nil {
					b.Fatal(err)
				}

				_ = body.Close()
			}
		})
	}
}
