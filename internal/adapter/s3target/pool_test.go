package s3target

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/port"
)

// fakeStore satisfies port.ObjectStore without a backend. The embedded nil
// interface is never called: the pool only hands stores back.
type fakeStore struct {
	port.ObjectStore
	id int
}

func target(bucket string) port.S3Target {
	return port.S3Target{
		Endpoint:  "https://s3.example.com",
		Region:    "us-east-1",
		Bucket:    bucket,
		AccessKey: "AKIA",
		SecretKey: "secret",
	}
}

func newCountingPool(t *testing.T, limit int) (*Pool, *atomic.Int32) {
	t.Helper()

	var calls atomic.Int32

	p := NewPool(PoolConfig{
		Max:           limit,
		SweepInterval: time.Hour,
		Builder: func(context.Context, port.S3Target) (port.ObjectStore, error) {
			return &fakeStore{id: int(calls.Add(1))}, nil
		},
	})
	t.Cleanup(p.Close)

	return p, &calls
}

func TestPoolReusesByFingerprint(t *testing.T) {
	t.Parallel()

	p, calls := newCountingPool(t, 4)
	ctx := context.Background()

	a1, err := p.Store(ctx, target("archive"))
	require.NoError(t, err)

	a2, err := p.Store(ctx, target("archive"))
	require.NoError(t, err)

	assert.Same(t, a1, a2)
	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, 1, p.len())

	rotated := target("archive")
	rotated.SecretKey = "new-secret"

	_, err = p.Store(ctx, rotated)
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load(), "a secret rotation must build a new store")
	assert.Equal(t, 2, p.len())

	withSSE := target("archive")
	withSSE.SSEKMS = &port.SSEKMS{KeyID: "alias/vault", BucketKey: true}

	_, err = p.Store(ctx, withSSE)
	require.NoError(t, err)
	assert.Equal(t, int32(3), calls.Load(), "SSE options must build a new store")

	withClass := target("archive")
	withClass.StorageClass = "STANDARD_IA"

	_, err = p.Store(ctx, withClass)
	require.NoError(t, err)
	assert.Equal(t, int32(4), calls.Load(), "a storage class change must build a new store")
}

func TestPoolEvictsLRU(t *testing.T) {
	t.Parallel()

	p, calls := newCountingPool(t, 1)
	ctx := context.Background()

	_, err := p.Store(ctx, target("a"))
	require.NoError(t, err)

	_, err = p.Store(ctx, target("b"))
	require.NoError(t, err)
	assert.Equal(t, 1, p.len())
	assert.Equal(t, int32(2), calls.Load())

	_, err = p.Store(ctx, target("a"))
	require.NoError(t, err)
	assert.Equal(t, 1, p.len())
	assert.Equal(t, int32(3), calls.Load(), "the evicted store is rebuilt")
}

func TestPoolSingleflight(t *testing.T) {
	t.Parallel()

	var (
		calls atomic.Int32
		wg    sync.WaitGroup
	)

	p := NewPool(PoolConfig{
		Max:           4,
		SweepInterval: time.Hour,
		Builder: func(context.Context, port.S3Target) (port.ObjectStore, error) {
			calls.Add(1)
			time.Sleep(30 * time.Millisecond)

			return &fakeStore{}, nil
		},
	})
	t.Cleanup(p.Close)

	for range 8 {
		wg.Go(func() {
			_, err := p.Store(context.Background(), target("archive"))
			assert.NoError(t, err)
		})
	}

	wg.Wait()

	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, 1, p.len())
}

func TestPoolDropsIdle(t *testing.T) {
	t.Parallel()

	p := NewPool(PoolConfig{
		Max:           4,
		Idle:          10 * time.Millisecond,
		SweepInterval: 10 * time.Millisecond,
		Builder: func(context.Context, port.S3Target) (port.ObjectStore, error) {
			return &fakeStore{}, nil
		},
	})
	t.Cleanup(p.Close)

	_, err := p.Store(context.Background(), target("archive"))
	require.NoError(t, err)
	assert.Equal(t, 1, p.len())

	require.Eventually(t, func() bool { return p.len() == 0 }, time.Second, 10*time.Millisecond)
}
