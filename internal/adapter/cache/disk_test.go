package cache

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/port"
)

func TestDiskPopulateGet(t *testing.T) {
	t.Parallel()
	d := newTestDisk(t, Options{TTL: time.Hour, MaxBytes: 1 << 20})
	id := ID("b", "k", "fp")
	p, err := d.Populate(context.Background(), id, port.EntryMeta{SHA256: "abc"}, func(w io.Writer) error {
		_, err := io.WriteString(w, "hello")
		return err
	})
	require.NoError(t, err)
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(b))

	got, hit, err := d.Get(context.Background(), id)
	require.NoError(t, err)
	assert.True(t, hit)
	assert.Equal(t, p, got)

	_, meta, hit, err := d.Lookup(context.Background(), id)
	require.NoError(t, err)
	assert.True(t, hit)
	assert.Equal(t, "abc", meta.SHA256)
	assert.False(t, meta.ValidatedAt.IsZero())

	require.NoError(t, d.Remove(context.Background(), id))
	_, hit, err = d.Get(context.Background(), id)
	require.NoError(t, err)
	assert.False(t, hit)
}

func TestDiskMarkValidated(t *testing.T) {
	t.Parallel()
	d := newTestDisk(t, Options{TTL: time.Hour, MaxBytes: 1 << 20})
	id := ID("b", "k", "fp")
	_, err := d.Populate(context.Background(), id, port.EntryMeta{SHA256: "a", ETag: "e1"}, func(w io.Writer) error {
		_, err := io.WriteString(w, "x")
		return err
	})
	require.NoError(t, err)
	_, before, hit, err := d.Lookup(context.Background(), id)
	require.NoError(t, err)
	require.True(t, hit)

	time.Sleep(5 * time.Millisecond)
	require.NoError(t, d.MarkValidated(context.Background(), id, port.EntryMeta{
		SHA256: "a", ETag: "e1", ValidatedAt: time.Now().UTC(),
	}))
	_, after, hit, err := d.Lookup(context.Background(), id)
	require.NoError(t, err)
	require.True(t, hit)
	assert.True(t, after.ValidatedAt.After(before.ValidatedAt))
}

func TestDiskPopulateReplacesOnIdentityChange(t *testing.T) {
	t.Parallel()
	d := newTestDisk(t, Options{TTL: time.Hour, MaxBytes: 1 << 20})
	id := ID("b", "k", "fp")
	_, err := d.Populate(context.Background(), id, port.EntryMeta{SHA256: "old"}, func(w io.Writer) error {
		_, err := io.WriteString(w, "old")
		return err
	})
	require.NoError(t, err)
	p, err := d.Populate(context.Background(), id, port.EntryMeta{SHA256: "new"}, func(w io.Writer) error {
		_, err := io.WriteString(w, "new")
		return err
	})
	require.NoError(t, err)
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, "new", string(b))
	_, meta, hit, err := d.Lookup(context.Background(), id)
	require.NoError(t, err)
	assert.True(t, hit)
	assert.Equal(t, "new", meta.SHA256)
}

func TestDiskTTLExpiry(t *testing.T) {
	t.Parallel()
	d := newTestDisk(t, Options{TTL: 20 * time.Millisecond, MaxBytes: 1 << 20})
	id := ID("b", "k", "fp")
	_, err := d.Populate(context.Background(), id, port.EntryMeta{}, func(w io.Writer) error {
		_, err := io.WriteString(w, "x")
		return err
	})
	require.NoError(t, err)
	time.Sleep(40 * time.Millisecond)
	_, hit, err := d.Get(context.Background(), id)
	require.NoError(t, err)
	assert.False(t, hit)
}

func TestDiskStampede(t *testing.T) {
	t.Parallel()
	d := newTestDisk(t, Options{TTL: time.Hour, MaxBytes: 1 << 20})
	id := ID("b", "k", "fp")
	var fills atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := d.Populate(context.Background(), id, port.EntryMeta{SHA256: "s"}, func(w io.Writer) error {
				fills.Add(1)
				time.Sleep(30 * time.Millisecond)
				_, err := io.WriteString(w, "body")
				return err
			})
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), fills.Load())
}

func TestDiskGetSkipsFreshAtimeWrite(t *testing.T) {
	t.Parallel()
	d := newTestDisk(t, Options{TTL: time.Hour, MaxBytes: 1 << 20})
	id := ID("b", "k", "fp")
	_, err := d.Populate(context.Background(), id, port.EntryMeta{}, func(w io.Writer) error {
		_, err := io.WriteString(w, "body")
		return err
	})
	require.NoError(t, err)

	_, metaRel, _, _, err := d.rel(id)
	require.NoError(t, err)
	before, err := d.readMeta(metaRel)
	require.NoError(t, err)

	_, hit, err := d.Get(context.Background(), id)
	require.NoError(t, err)
	require.True(t, hit)

	after, err := d.readMeta(metaRel)
	require.NoError(t, err)
	assert.Equal(t, before.ATime, after.ATime)
	assert.Equal(t, before.SHA256, after.SHA256)
}

func TestDiskConcurrentGetMeta(t *testing.T) {
	t.Parallel()
	d := newTestDisk(t, Options{TTL: time.Hour, MaxBytes: 1 << 20})
	id := ID("b", "k", "fp")
	_, err := d.Populate(context.Background(), id, port.EntryMeta{SHA256: "x"}, func(w io.Writer) error {
		_, err := io.WriteString(w, "body")
		return err
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_, hit, err := d.Get(context.Background(), id)
				if err != nil {
					errCh <- err
					return
				}
				if !hit {
					errCh <- errors.New("expected cache hit")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}

	_, hit, err := d.Get(context.Background(), id)
	require.NoError(t, err)
	assert.True(t, hit)
	_, metaRel, _, _, err := d.rel(id)
	require.NoError(t, err)
	_, err = d.readMeta(metaRel)
	require.NoError(t, err)
}

func TestDiskLRU(t *testing.T) {
	t.Parallel()
	d := newTestDisk(t, Options{TTL: time.Hour, MaxBytes: 8})
	fill := func(id port.CacheID, s string) {
		_, err := d.Populate(context.Background(), id, port.EntryMeta{}, func(w io.Writer) error {
			_, err := io.WriteString(w, s)
			return err
		})
		require.NoError(t, err)
	}
	a := ID("b", "a", "fp")
	b := ID("b", "b", "fp")
	c := ID("b", "c", "fp")
	fill(a, "aaaa")
	time.Sleep(5 * time.Millisecond)
	fill(b, "bbbb")
	time.Sleep(5 * time.Millisecond)
	fill(c, "cccc")
	_, hitA, err := d.Get(context.Background(), a)
	require.NoError(t, err)
	assert.False(t, hitA)
	_, hitC, err := d.Get(context.Background(), c)
	require.NoError(t, err)
	assert.True(t, hitC)
}

func TestDiskSweepExpired(t *testing.T) {
	t.Parallel()
	d := newTestDisk(t, Options{TTL: 20 * time.Millisecond, MaxBytes: 1 << 20})
	keep := ID("b", "keep", "fp")
	drop := ID("b", "drop", "fp")
	_, err := d.Populate(context.Background(), keep, port.EntryMeta{}, func(w io.Writer) error {
		_, err := io.WriteString(w, "keep")
		return err
	})
	require.NoError(t, err)
	_, err = d.Populate(context.Background(), drop, port.EntryMeta{}, func(w io.Writer) error {
		_, err := io.WriteString(w, "drop")
		return err
	})
	require.NoError(t, err)

	dataRel, metaRel, _, _, err := d.rel(keep)
	require.NoError(t, err)
	sc, err := d.readMeta(metaRel)
	require.NoError(t, err)
	sc.ExpiresAt = time.Now().UTC().Add(time.Hour)
	require.NoError(t, d.writeMeta(metaRel, sc))
	d.remember(string(keep), dataRel, metaRel, sc)

	time.Sleep(40 * time.Millisecond)
	assert.Equal(t, 1, d.SweepExpired())

	_, hitKeep, err := d.Get(context.Background(), keep)
	require.NoError(t, err)
	assert.True(t, hitKeep)
	_, hitDrop, err := d.Get(context.Background(), drop)
	require.NoError(t, err)
	assert.False(t, hitDrop)

	st, err := d.Usage()
	require.NoError(t, err)
	assert.Equal(t, 1, st.Entries)
}

func TestDiskStartSweeper(t *testing.T) {
	t.Parallel()
	d := newTestDisk(t, Options{TTL: 30 * time.Millisecond, MaxBytes: 1 << 20})
	id := ID("b", "sweep", "fp")
	_, err := d.Populate(context.Background(), id, port.EntryMeta{}, func(w io.Writer) error {
		_, err := io.WriteString(w, "x")
		return err
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.StartSweeper(ctx, 20*time.Millisecond, nil)

	require.Eventually(t, func() bool {
		st, err := d.Usage()
		return err == nil && st.Entries == 0
	}, time.Second, 10*time.Millisecond)
}

func TestDiskRemoveCleansLockAndShard(t *testing.T) {
	t.Parallel()
	d := newTestDisk(t, Options{TTL: time.Hour, MaxBytes: 1 << 20})
	id := ID("b", "k", "fp")
	_, err := d.Populate(context.Background(), id, port.EntryMeta{}, func(w io.Writer) error {
		_, err := io.WriteString(w, "hello")
		return err
	})
	require.NoError(t, err)

	dataRel, _, lockRel, _, err := d.rel(id)
	require.NoError(t, err)
	shard := path.Dir(dataRel)

	// Simulate stale lock left by an older version or crashed populate.
	require.NoError(t, d.root.WriteFile(lockRel, nil, 0o600))

	require.NoError(t, d.Remove(context.Background(), id))

	_, err = d.root.Stat(dataRel)
	require.True(t, os.IsNotExist(err))
	_, err = d.root.Stat(lockRel)
	require.True(t, os.IsNotExist(err))
	_, err = d.root.Open(shard)
	require.True(t, os.IsNotExist(err), "empty shard directory should be removed")
}

func TestDiskSweepExpiredCleansLockAndShard(t *testing.T) {
	t.Parallel()
	d := newTestDisk(t, Options{TTL: 20 * time.Millisecond, MaxBytes: 1 << 20})
	id := ID("b", "drop", "fp")
	_, err := d.Populate(context.Background(), id, port.EntryMeta{}, func(w io.Writer) error {
		_, err := io.WriteString(w, "drop")
		return err
	})
	require.NoError(t, err)

	dataRel, _, lockRel, _, err := d.rel(id)
	require.NoError(t, err)
	shard := path.Dir(dataRel)

	// Lock is removed after Populate; sweep must still drop stale locks.
	require.NoError(t, d.root.WriteFile(lockRel, nil, 0o600))

	time.Sleep(40 * time.Millisecond)
	assert.Equal(t, 1, d.SweepExpired())

	_, err = d.root.Stat(dataRel)
	require.True(t, os.IsNotExist(err))
	_, err = d.root.Stat(lockRel)
	require.True(t, os.IsNotExist(err))
	_, err = d.root.Open(shard)
	require.True(t, os.IsNotExist(err), "empty shard directory should be removed after sweep")
}

func TestDiskRejectsBadID(t *testing.T) {
	t.Parallel()
	d := newTestDisk(t, Options{})
	_, _, err := d.Get(context.Background(), port.CacheID("../etc/passwd"))
	require.Error(t, err)
}

func newTestDisk(t *testing.T, opt Options) *Disk {
	t.Helper()
	opt.Dir = t.TempDir()
	d, err := New(opt)
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })
	return d
}
