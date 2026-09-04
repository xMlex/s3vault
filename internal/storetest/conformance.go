// Package storetest holds the shared contract checks every ObjectStore backend
// must satisfy, so S3 and the local filesystem cannot drift apart.
package storetest

import (
	"bytes"
	"context"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/port"
)

// Factory opens a store plus a key prefix that isolates one test run.
// The prefix must end with "/" (or be empty for a private store).
type Factory func(t *testing.T) (port.ObjectStore, string)

// RunConformance exercises the port.ObjectStore contract: not-found
// semantics, inclusive ranges, overwrite, idempotent delete and prefix list.
// Only behavior shared by every backend belongs here.
func RunConformance(t *testing.T, newStore Factory) {
	t.Helper()

	t.Run("head missing object reports absence without error", func(t *testing.T) {
		store, prefix := newStore(t)
		meta, err := store.Head(context.Background(), prefix+"missing.bin")
		require.NoError(t, err)
		assert.False(t, meta.Exists)
	})

	t.Run("read missing object returns ErrNotFound", func(t *testing.T) {
		store, prefix := newStore(t)
		ctx := context.Background()
		_, _, err := store.Get(ctx, prefix+"missing.bin")
		require.ErrorIs(t, err, domain.ErrNotFound)
		_, _, err = store.GetRange(ctx, prefix+"missing.bin", 0, 127)
		require.ErrorIs(t, err, domain.ErrNotFound)
	})

	t.Run("put then get returns the same bytes", func(t *testing.T) {
		store, prefix := newStore(t)
		ctx := context.Background()
		key := prefix + "roundtrip.bin"
		body := []byte("s3vault conformance payload")
		put(t, store, key, body)

		meta, err := store.Head(ctx, key)
		require.NoError(t, err)
		assert.True(t, meta.Exists)
		assert.Equal(t, int64(len(body)), meta.Size)

		rc, getMeta, err := store.Get(ctx, key)
		require.NoError(t, err)
		got, err := io.ReadAll(rc)
		require.NoError(t, rc.Close())
		require.NoError(t, err)
		assert.Equal(t, body, got)
		assert.True(t, getMeta.Exists)
	})

	t.Run("get range bounds are inclusive", func(t *testing.T) {
		store, prefix := newStore(t)
		key := prefix + "range.bin"
		put(t, store, key, []byte("0123456789"))

		assert.Equal(t, "0123", readRange(t, store, key, 0, 3))
		assert.Equal(t, "456", readRange(t, store, key, 4, 6))
		assert.Equal(t, "9", readRange(t, store, key, 9, 9))
	})

	t.Run("put overwrites an existing object", func(t *testing.T) {
		store, prefix := newStore(t)
		key := prefix + "overwrite.bin"
		put(t, store, key, []byte("first"))
		put(t, store, key, []byte("second value"))

		meta, err := store.Head(context.Background(), key)
		require.NoError(t, err)
		assert.Equal(t, int64(len("second value")), meta.Size)
	})

	t.Run("delete is idempotent", func(t *testing.T) {
		store, prefix := newStore(t)
		ctx := context.Background()
		key := prefix + "delete.bin"
		put(t, store, key, []byte("bye"))

		require.NoError(t, store.Delete(ctx, key))
		meta, err := store.Head(ctx, key)
		require.NoError(t, err)
		assert.False(t, meta.Exists)
		require.NoError(t, store.Delete(ctx, key))
	})

	t.Run("list returns objects under a prefix", func(t *testing.T) {
		store, prefix := newStore(t)
		put(t, store, prefix+"list/a.bin", []byte("a"))
		put(t, store, prefix+"list/b.bin", []byte("b"))
		put(t, store, prefix+"other.bin", []byte("c"))

		page, err := store.List(context.Background(), domain.ListOptions{Prefix: prefix + "list/"})
		require.NoError(t, err)
		keys := make([]string, 0, len(page.Contents))
		for _, obj := range page.Contents {
			keys = append(keys, obj.Key)
		}
		slices.Sort(keys)
		assert.Equal(t, []string{prefix + "list/a.bin", prefix + "list/b.bin"}, keys)
	})
}

func put(t *testing.T, store port.ObjectStore, key string, body []byte) {
	t.Helper()
	require.NoError(t, store.Put(context.Background(), key, bytes.NewReader(body), domain.PutMeta{}))
	t.Cleanup(func() { _ = store.Delete(context.Background(), key) })
}

func readRange(t *testing.T, store port.ObjectStore, key string, start, end int64) string {
	t.Helper()
	rc, _, err := store.GetRange(context.Background(), key, start, end)
	require.NoError(t, err)
	got, err := io.ReadAll(rc)
	require.NoError(t, rc.Close())
	require.NoError(t, err)
	return string(got)
}
