package service_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/cache"
	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/service"
)

type countingStore struct {
	*memStore
	heads  atomic.Int64
	gets   atomic.Int64
	ranges atomic.Int64
}

func (c *countingStore) Head(ctx context.Context, key string) (domain.ObjectMeta, error) {
	c.heads.Add(1)
	return c.memStore.Head(ctx, key)
}

func (c *countingStore) Get(ctx context.Context, key string) (io.ReadCloser, domain.ObjectMeta, error) {
	c.gets.Add(1)
	return c.memStore.Get(ctx, key)
}

func (c *countingStore) GetRange(ctx context.Context, key string, start, end int64) (io.ReadCloser, domain.ObjectMeta, error) {
	c.ranges.Add(1)
	return c.memStore.GetRange(ctx, key, start, end)
}

func TestFetchMaterialize(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	plain := []byte("hello")
	putContained(t, store, "k", plain)
	sum := sha256.Sum256(plain)
	wantETag := hex.EncodeToString(sum[:])

	disk, err := cache.New(cache.Options{Dir: t.TempDir(), TTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })

	f := service.NewFetch(store, encrypt.Passthrough{}).
		WithCache(disk, "bucket", "fp").
		WithSoftTTL(time.Minute)
	got, err := f.Materialize(context.Background(), "k")
	require.NoError(t, err)
	assert.False(t, got.Hit)
	b, err := os.ReadFile(got.Path)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(b))
	assert.Equal(t, wantETag, got.ETag)

	got2, err := f.Materialize(context.Background(), "k")
	require.NoError(t, err)
	assert.True(t, got2.Hit)

	_, err = f.Materialize(context.Background(), "missing")
	require.ErrorIs(t, err, domain.ErrNotFound)
}

func TestFetchMaterializeEphemeral(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	plain := []byte("ephemeral-body")
	putContained(t, store, "k", plain)
	sum := sha256.Sum256(plain)

	f := service.NewFetch(store, encrypt.Passthrough{})
	got, err := f.Materialize(context.Background(), "k")
	require.NoError(t, err)
	assert.True(t, got.Ephemeral)
	assert.False(t, got.Hit)
	assert.Equal(t, hex.EncodeToString(sum[:]), got.ETag)
	b, err := os.ReadFile(got.Path)
	require.NoError(t, err)
	assert.Equal(t, plain, b)
	got.Release()
	_, err = os.Stat(got.Path)
	assert.ErrorIs(t, err, os.ErrNotExist)

	_, err = f.Materialize(context.Background(), "missing")
	require.ErrorIs(t, err, domain.ErrNotFound)
}

// gatedGetStore blocks the first Get of one key until the gate is closed, so a
// test can interleave an invalidation into a running populate.
type gatedGetStore struct {
	*memStore
	key  string
	gate chan struct{}
	gets atomic.Int64
}

func (g *gatedGetStore) Get(ctx context.Context, key string) (io.ReadCloser, domain.ObjectMeta, error) {
	if key == g.key && g.gets.Add(1) == 1 {
		<-g.gate
	}

	return g.memStore.Get(ctx, key)
}

// A populate that raced an invalidation must not commit the pre-PUT version:
// the removal during the fill makes the fill discard itself, and the read
// retries with the version that is current afterwards (problems.md D6/D14).
func TestFetchPopulateInvalidatedMidDownloadServesCurrentVersion(t *testing.T) {
	t.Parallel()

	inner := newMemStore()
	putContained(t, inner, "k", []byte("v1"))
	store := &gatedGetStore{memStore: inner, key: "k", gate: make(chan struct{})}
	disk, err := cache.New(cache.Options{Dir: t.TempDir(), TTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })

	f := service.NewFetch(store, encrypt.Passthrough{}).
		WithCache(disk, "bucket", "fp").
		WithSoftTTL(time.Minute)

	type result struct {
		got service.CachedPlaintext
		err error
	}

	ch := make(chan result, 1)

	go func() {
		got, err := f.Materialize(context.Background(), "k")
		ch <- result{got, err}
	}()

	// Wait until the populate is blocked inside store.Get, holding the entry's
	// lock with a live temp file.
	require.Eventually(t, func() bool {
		return store.gets.Load() == 1
	}, time.Second, 2*time.Millisecond)

	require.NoError(t, disk.Remove(context.Background(), cache.ID("bucket", "k", "fp")))
	putContained(t, inner, "k", []byte("v2"))
	close(store.gate)

	res := <-ch
	require.NoError(t, res.err)
	b, err := os.ReadFile(res.got.Path)
	require.NoError(t, err)
	assert.Equal(t, "v2", string(b), "the read must retry with the version that is current after the invalidation")
	assert.Equal(t, int64(2), store.gets.Load(), "the discarded fill consumed one Get; the retry downloaded the fresh version")
}

func TestFetchMaterializeSoftTTLSkipsHead(t *testing.T) {
	t.Parallel()
	inner := newMemStore()
	putContained(t, inner, "k", []byte("hello"))
	store := &countingStore{memStore: inner}
	disk, err := cache.New(cache.Options{Dir: t.TempDir(), TTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })

	f := service.NewFetch(store, encrypt.Passthrough{}).
		WithCache(disk, "bucket", "fp").
		WithSoftTTL(time.Minute)

	_, err = f.Materialize(context.Background(), "k")
	require.NoError(t, err)
	headsAfterMiss := store.heads.Load()
	getsAfterMiss := store.gets.Load()
	// A cold miss reads the object once. Its identity comes from the S3VCTR01
	// header of that same stream, so there is no HEAD (and no 128-byte Range)
	// before it.
	assert.Equal(t, int64(0), headsAfterMiss)
	assert.Equal(t, int64(1), getsAfterMiss)

	_, err = f.Materialize(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, headsAfterMiss, store.heads.Load(), "soft-fresh hit must not HEAD")
	assert.Equal(t, getsAfterMiss, store.gets.Load(), "soft-fresh hit must not GET")
}

func TestFetchMaterializeSWRRevalidates(t *testing.T) {
	t.Parallel()
	inner := newMemStore()
	putContained(t, inner, "k", []byte("hello"))
	store := &countingStore{memStore: inner}
	disk, err := cache.New(cache.Options{Dir: t.TempDir(), TTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })

	f := service.NewFetch(store, encrypt.Passthrough{}).
		WithCache(disk, "bucket", "fp").
		WithSoftTTL(20 * time.Millisecond)

	_, err = f.Materialize(context.Background(), "k")
	require.NoError(t, err)
	time.Sleep(40 * time.Millisecond)

	headsBefore := store.heads.Load()
	rangesBefore := store.ranges.Load()
	getsBefore := store.gets.Load()

	// A stale Materialize must only mark the entry: it must not start the
	// background refresh itself. The refresh is scheduled by Open after the
	// body is pinned, which is what keeps headers and bytes from different
	// generations apart (problems.md D13).
	stale, err := f.Materialize(context.Background(), "k")
	require.NoError(t, err)
	assert.True(t, stale.Hit)
	require.Never(t, func() bool {
		return store.ranges.Load() > rangesBefore
	}, 100*time.Millisecond, 10*time.Millisecond, "Materialize must not start revalidation before the body is pinned")

	// Open is the serving path: it pins the body and schedules the background
	// refresh only afterwards.
	rc, got, err := f.Open(context.Background(), "k")
	require.NoError(t, err)
	assert.True(t, got.Hit)

	require.Eventually(t, func() bool {
		return store.ranges.Load() > rangesBefore
	}, time.Second, 5*time.Millisecond)
	assert.Equal(t, headsBefore, store.heads.Load(), "container identity comes from the header range, not HEAD")
	assert.Equal(t, getsBefore, store.gets.Load(), "unchanged object must not re-GET")

	require.NoError(t, rc.Close())
}

func TestFetchMaterializeSWRRepopulatesOnChange(t *testing.T) {
	t.Parallel()
	inner := newMemStore()
	putContained(t, inner, "k", []byte("v1"))
	store := &countingStore{memStore: inner}
	disk, err := cache.New(cache.Options{Dir: t.TempDir(), TTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })

	f := service.NewFetch(store, encrypt.Passthrough{}).
		WithCache(disk, "bucket", "fp").
		WithSoftTTL(20 * time.Millisecond)

	first, err := f.Materialize(context.Background(), "k")
	require.NoError(t, err)
	b, err := os.ReadFile(first.Path)
	require.NoError(t, err)
	assert.Equal(t, "v1", string(b))

	putContained(t, inner, "k", []byte("v2"))
	time.Sleep(40 * time.Millisecond)

	// Open a stale hit, then let the scheduled revalidation repopulate while
	// this reader is still open.
	rc, got, err := f.Open(context.Background(), "k")
	require.NoError(t, err)
	assert.True(t, got.Hit) // stale served immediately

	stale, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "v1", string(stale), "the pinned reader must keep serving the version whose identity the response advertises")
	require.NoError(t, rc.Close())

	require.Eventually(t, func() bool {
		b, err := os.ReadFile(got.Path)
		return err == nil && string(b) == "v2"
	}, 2*time.Second, 10*time.Millisecond)
}
