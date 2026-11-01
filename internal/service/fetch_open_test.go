package service_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	localstore "github.com/xMlex/s3vault/internal/adapter/local"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/service"
)

// countingReader counts the bytes a store actually handed out.
type countingReader struct {
	r io.ReadCloser
	n *int64
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	*c.n += int64(n)

	return n, err
}

func (c countingReader) Close() error { return c.r.Close() }

// rangeCountingStore wraps memStore and records how much of the body was read and how
// many requests reached it. The point of a ranged read is the number it keeps
// small.
type rangeCountingStore struct {
	*memStore

	mu      sync.Mutex
	bytes   int64
	heads   int
	gets    int
	ranges  int
	request int64 // bytes a GetRange asked for
}

func (c *rangeCountingStore) Head(ctx context.Context, key string) (domain.ObjectMeta, error) {
	c.mu.Lock()
	c.heads++
	c.mu.Unlock()

	return c.memStore.Head(ctx, key)
}

func (c *rangeCountingStore) Get(ctx context.Context, key string) (io.ReadCloser, domain.ObjectMeta, error) {
	body, meta, err := c.memStore.Get(ctx, key)
	if err != nil {
		return body, meta, err
	}

	c.mu.Lock()
	c.gets++
	c.mu.Unlock()

	return countingReader{r: body, n: &c.bytes}, meta, nil
}

func (c *rangeCountingStore) GetRange(ctx context.Context, key string, start, end int64) (io.ReadCloser, domain.ObjectMeta, error) {
	body, meta, err := c.memStore.GetRange(ctx, key, start, end)
	if err != nil {
		return body, meta, err
	}

	c.mu.Lock()

	c.ranges++
	if end >= start {
		c.request += end - start + 1
	}
	c.mu.Unlock()

	return countingReader{r: body, n: &c.bytes}, meta, nil
}

func (c *rangeCountingStore) counts() (bytesRead, requests int64, heads, gets, ranges int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.bytes, c.request, c.heads, c.gets, c.ranges
}

func nativeEncryptor(t *testing.T) *encrypt.Native {
	t.Helper()

	keyFile := t.TempDir() + "/kek"
	require.NoError(t, os.WriteFile(keyFile, make([]byte, 32), 0o600))

	n, err := encrypt.NewNative(config.NativeEnc{Wrap: "keyfile", KeyFile: keyFile, ChunkSize: 1024})
	require.NoError(t, err)

	return n
}

// TestFetchStatContainerlessModeNoneUsesHeadWithoutDownload is the HEAD contract
// for encryption.mode=none objects: stored size is plaintext size and Head
// carries the digest, so neither a body read nor a materialization is needed.
func TestFetchStatContainerlessModeNoneUsesHeadWithoutDownload(t *testing.T) {
	t.Parallel()

	plain := bytes.Repeat([]byte("x"), 4<<20)
	inner := newMemStore()
	sum := sha256Hex(plain)
	require.NoError(t, inner.Put(context.Background(), "k", bytes.NewReader(plain), domain.PutMeta{
		PlaintextSHA256: sum,
	}))

	store := &rangeCountingStore{memStore: inner}
	f := service.NewFetch(store, encrypt.Passthrough{})

	got, err := f.Stat(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, int64(len(plain)), got.Size)
	assert.Equal(t, sum, got.SHA256)
	assert.Empty(t, got.Path)

	bytesRead, _, heads, gets, ranges := store.counts()
	assert.Equal(t, 1, heads)
	assert.Equal(t, 0, gets, "HEAD must not materialize a containerless object")
	assert.Equal(t, 1, ranges)
	assert.LessOrEqual(t, bytesRead, int64(container.HeaderSize))
}

// TestFetchStatReadsNoBody is the HEAD contract: metadata only.
func TestFetchStatReadsNoBody(t *testing.T) {
	t.Parallel()

	plain := bytes.Repeat([]byte("x"), 4<<20)
	inner := newMemStore()
	putContained(t, inner, "k", plain)

	store := &rangeCountingStore{memStore: inner}
	f := service.NewFetch(store, encrypt.Passthrough{})

	got, err := f.Stat(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, int64(len(plain)), got.Size)
	assert.Equal(t, sha256Hex(plain), got.SHA256)
	assert.Empty(t, got.Path, "a HEAD has nothing to open")

	bytesRead, _, heads, gets, ranges := store.counts()
	assert.Equal(t, 1, heads)
	assert.Equal(t, 0, gets, "HEAD must not download the body")
	assert.Equal(t, 1, ranges, "identity comes from the 128-byte header range")
	assert.LessOrEqual(t, bytesRead, int64(container.HeaderSize))
}

func TestFetchStatMissing(t *testing.T) {
	t.Parallel()

	f := service.NewFetch(newMemStore(), encrypt.Passthrough{})
	_, err := f.Stat(context.Background(), "missing")
	require.ErrorIs(t, err, domain.ErrNotFound)
}

// TestFetchOpenRangedPlaintext proves a range read fetches the window, not the
// object.
func TestFetchOpenRangedPlaintext(t *testing.T) {
	t.Parallel()

	plain := make([]byte, 8<<20)
	for i := range plain {
		plain[i] = byte(i)
	}

	inner := newMemStore()
	putContained(t, inner, "k", plain)

	store := &rangeCountingStore{memStore: inner}
	f := service.NewFetch(store, encrypt.Passthrough{})

	rc, meta, err := f.Open(context.Background(), "k")
	require.NoError(t, err)

	defer func() { _ = rc.Close() }()

	assert.Equal(t, int64(len(plain)), meta.Size)
	assert.Equal(t, sha256Hex(plain), meta.ETag)

	// Read 1 KiB from the middle, the way a ranged GET does.
	const at = 5 << 20

	_, err = rc.Seek(at, io.SeekStart)
	require.NoError(t, err)

	got := make([]byte, 1024)
	_, err = io.ReadFull(rc, got)
	require.NoError(t, err)
	assert.Equal(t, plain[at:at+1024], got)

	bytesRead, requested, _, _, _ := store.counts()
	// One 64 KiB prefix probe plus the 1 MiB window around the read.
	assert.Less(t, bytesRead, int64(2<<20), "a 1 KiB range must not read the 8 MiB object")
	assert.Less(t, requested, int64(2<<20))
}

func TestFetchOpenRangedNative(t *testing.T) {
	t.Parallel()

	plain := make([]byte, 8<<20) // not a multiple of the 1 KiB chunk
	for i := range plain {
		plain[i] = byte(i * 7)
	}

	enc := nativeEncryptor(t)

	var cipher bytes.Buffer
	require.NoError(t, enc.Encrypt(context.Background(), &cipher, bytes.NewReader(plain)))

	sum := sha256.Sum256(plain)
	hdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: int64(len(plain)),
		SHA256:        sum[:],
		Enc:           container.EncNative,
		Wrap:          container.WrapFromName("keyfile"),
	})
	require.NoError(t, err)

	inner := newMemStore()
	require.NoError(t, inner.Put(context.Background(), "k",
		io.MultiReader(bytes.NewReader(hdr), bytes.NewReader(cipher.Bytes())), domain.PutMeta{}))

	store := &rangeCountingStore{memStore: inner}
	f := service.NewFetch(store, enc)

	rc, meta, err := f.Open(context.Background(), "k")
	require.NoError(t, err)

	defer func() { _ = rc.Close() }()

	assert.Equal(t, int64(len(plain)), meta.Size)

	tests := []struct {
		name   string
		offset int64
		length int64
	}{
		{name: "start", offset: 0, length: 100},
		{name: "chunk boundary", offset: 1024, length: 1},
		{name: "unaligned cross-chunk", offset: 1500, length: 3000},
		{name: "tail", offset: int64(len(plain)) - 10, length: 10},
	}

	// The subtests share one request-scoped reader, so they cannot run in parallel.
	for _, tt := range tests { //nolint:paralleltest // one reader, sequential reads
		t.Run(tt.name, func(t *testing.T) {
			before, _, _, _, _ := store.counts()

			_, err := rc.Seek(tt.offset, io.SeekStart)
			require.NoError(t, err)

			got := make([]byte, tt.length)
			_, err = io.ReadFull(rc, got)
			require.NoError(t, err)
			assert.Equal(t, plain[tt.offset:tt.offset+tt.length], got)

			after, _, _, _, _ := store.counts()
			// One plaintext window plus the framing of the chunks around it.
			assert.Less(t, after-before, int64(2<<20), "one window per read")
		})
	}

	bytesRead, _, _, _, _ := store.counts()
	assert.Less(t, bytesRead, int64(len(plain)), "ranged reads must not fetch the whole object")
}

// TestFetchOpenFallsBackForCommand keeps the contract for layers with no random
// access: a command-mode object is materialized and served from the temp file.
func TestFetchOpenFallsBackForCommand(t *testing.T) {
	t.Parallel()

	payload := []byte("ciphertext-of-unknown-shape")
	store := newMemStore()
	require.NoError(t, store.Put(context.Background(), "k",
		bytes.NewReader(containedPayload(t, container.EncCommand, payload)), domain.PutMeta{}))

	marker := t.TempDir() + "/invoked"
	enc := recordingCommand(t, marker)

	rc, meta, err := service.NewFetch(store, enc).Open(context.Background(), "k")
	require.NoError(t, err)

	defer func() { _ = rc.Close() }()

	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, payload, b)
	assert.Equal(t, "ciphertext-of-unknown-shape", string(b))
	assert.FileExists(t, marker)
	assert.NotEmpty(t, meta.Path)
}

// TestFetchOpenContainerlessPlaintext covers mode=none objects written without a
// container: the stored bytes are the plaintext, so they can be ranged directly.
// TestFetchOpenLocalContainerlessETag pins GET/HEAD consistency on the local
// backend: GetRange carries only the synthetic size+mtime validator, so the
// ranged reader must take the digest from Head. Otherwise GET advertises a
// different ETag than HEAD for the same containerless object.
func TestFetchOpenLocalContainerlessETag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	plain := bytes.Repeat([]byte("abc"), 1000)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "k"), plain, 0o600))

	st, err := localstore.New(config.LocalConfig{Dir: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	f := service.NewFetch(st, encrypt.Passthrough{})

	rc, meta, err := f.Open(context.Background(), "k")
	require.NoError(t, err)
	t.Cleanup(func() { _ = rc.Close() })

	want := sha256Hex(plain)
	assert.Equal(t, want, meta.SHA256)
	assert.Equal(t, want, meta.ETag, "GET ETag must be the content digest, not the synthetic validator")
	assert.Equal(t, int64(len(plain)), meta.Size)

	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}

func TestFetchOpenContainerlessPlaintext(t *testing.T) {
	t.Parallel()

	plain := bytes.Repeat([]byte("abc"), 1000)
	inner := newMemStore()
	require.NoError(t, inner.Put(context.Background(), "k", bytes.NewReader(plain), domain.PutMeta{
		PlaintextSHA256: sha256Hex(plain),
		PlaintextSize:   int64(len(plain)),
	}))

	store := &rangeCountingStore{memStore: inner}
	f := service.NewFetch(store, encrypt.Passthrough{})

	rc, meta, err := f.Open(context.Background(), "k")
	require.NoError(t, err)

	defer func() { _ = rc.Close() }()

	_, err = rc.Seek(100, io.SeekStart)
	require.NoError(t, err)

	got := make([]byte, 10)
	_, err = io.ReadFull(rc, got)
	require.NoError(t, err)
	assert.Equal(t, plain[100:110], got)
	assert.Equal(t, int64(len(plain)), meta.Size)
	assert.Equal(t, sha256Hex(plain), meta.SHA256)
}

// rangeSizedStore models an S3 GetRange response: Content-Length describes the
// returned range, while the object's plaintext length is only in ContentSize.
type rangeSizedStore struct {
	*memStore
}

func (s *rangeSizedStore) GetRange(ctx context.Context, key string, start, end int64) (io.ReadCloser, domain.ObjectMeta, error) {
	body, meta, err := s.memStore.GetRange(ctx, key, start, end)
	if err != nil {
		return body, meta, err
	}

	meta.Size = end - start + 1

	return body, meta, nil
}

// TestFetchOpenContainerlessUsesDeclaredSize pins the size source for a
// containerless object on a store whose GetRange reports the range length: the
// declared plaintext size must win, or a read past the prefix window is cut off.
func TestFetchOpenContainerlessUsesDeclaredSize(t *testing.T) {
	t.Parallel()

	plain := bytes.Repeat([]byte("abc"), 100_000) // larger than the prefix probe
	inner := newMemStore()
	require.NoError(t, inner.Put(context.Background(), "k", bytes.NewReader(plain), domain.PutMeta{
		PlaintextSHA256: sha256Hex(plain),
		PlaintextSize:   int64(len(plain)),
	}))

	f := service.NewFetch(&rangeSizedStore{memStore: inner}, encrypt.Passthrough{})

	rc, meta, err := f.Open(context.Background(), "k")
	require.NoError(t, err)
	t.Cleanup(func() { _ = rc.Close() })

	assert.Equal(t, int64(len(plain)), meta.Size)

	const tail = 10
	_, err = rc.Seek(meta.Size-tail, io.SeekStart)
	require.NoError(t, err)

	got := make([]byte, tail)
	_, err = io.ReadFull(rc, got)
	require.NoError(t, err)
	assert.Equal(t, plain[len(plain)-tail:], got)
}

// TestFetchMaterializeEphemeralShared pins the cold-read collapse: sixteen
// readers of one key cause one download, and the file survives until the last
// Release.
func TestFetchMaterializeEphemeralShared(t *testing.T) {
	t.Parallel()

	plain := bytes.Repeat([]byte("shared"), 10_000)
	inner := newMemStore()
	putContained(t, inner, "k", plain)

	store := &rangeCountingStore{memStore: inner}
	f := service.NewFetch(store, encrypt.Passthrough{}).WithSpoolDir(t.TempDir())

	const readers = 16

	var wg sync.WaitGroup

	got := make([]service.CachedPlaintext, readers)
	errs := make([]error, readers)

	start := make(chan struct{})

	for i := range readers {
		wg.Go(func() {
			<-start

			got[i], errs[i] = f.Materialize(context.Background(), "k")
		})
	}

	close(start)
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}

	for i := 1; i < readers; i++ {
		assert.Equal(t, got[0].Path, got[i].Path, "every reader must share one plaintext file")
	}

	_, _, _, gets, _ := store.counts()
	assert.Equal(t, 1, gets, "concurrent cold reads must collapse to one download")

	b, err := os.ReadFile(got[0].Path)
	require.NoError(t, err)
	assert.Equal(t, plain, b)

	// The file lives until the last reference is released.
	for i, c := range got {
		if i == readers-1 {
			break
		}

		c.Release()
		assert.FileExists(t, got[0].Path, "still referenced by the last reader")
	}

	got[readers-1].Release()
	assert.NoFileExists(t, got[0].Path, "the last Release removes the shared file")
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
