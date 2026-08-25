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
	heads atomic.Int64
	gets  atomic.Int64
}

func (c *countingStore) Head(ctx context.Context, key string) (domain.ObjectMeta, error) {
	c.heads.Add(1)
	return c.memStore.Head(ctx, key)
}

func (c *countingStore) Get(ctx context.Context, key string) (io.ReadCloser, domain.ObjectMeta, error) {
	c.gets.Add(1)
	return c.memStore.Get(ctx, key)
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
	assert.Equal(t, int64(1), headsAfterMiss)
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
	getsBefore := store.gets.Load()
	got, err := f.Materialize(context.Background(), "k")
	require.NoError(t, err)
	assert.True(t, got.Hit)

	require.Eventually(t, func() bool {
		return store.heads.Load() > headsBefore
	}, time.Second, 5*time.Millisecond)
	assert.Equal(t, getsBefore, store.gets.Load(), "unchanged object must not re-GET")
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

	got, err := f.Materialize(context.Background(), "k")
	require.NoError(t, err)
	assert.True(t, got.Hit) // stale served immediately

	require.Eventually(t, func() bool {
		b, err := os.ReadFile(got.Path)
		return err == nil && string(b) == "v2"
	}, 2*time.Second, 10*time.Millisecond)
}
