package httpserver_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/cache"
	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/httpserver"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/service"
)

type memStore struct {
	mu   sync.Mutex
	meta map[string]domain.ObjectMeta
	body map[string][]byte
}

func newMemStore() *memStore {
	return &memStore{meta: map[string]domain.ObjectMeta{}, body: map[string][]byte{}}
}

func (m *memStore) Head(_ context.Context, key string) (domain.ObjectMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	meta, ok := m.meta[key]
	if !ok {
		return domain.ObjectMeta{Key: key, Exists: false}, nil
	}
	return meta, nil
}

func (m *memStore) Put(_ context.Context, key string, r io.Reader, _ domain.PutMeta) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	om := domain.ObjectMeta{
		Key:          key,
		Exists:       true,
		Size:         int64(len(b)),
		ETag:         `"etag-` + key + `"`,
		LastModified: time.Unix(1_700_000_000, 0).UTC(),
	}
	if len(b) >= container.HeaderSize && container.IsMagic(b) {
		if hdr, err := container.Parse(b[:container.HeaderSize]); err == nil {
			om.SHA256 = hdr.SHA256Hex()
			om.ContentSize = hdr.PlaintextSize
			om.Encrypted = container.EncName(hdr.Enc)
			om.Wrap = container.WrapName(hdr.Wrap)
			om.Provider = hdr.Provider
			om.FormatVersion = container.FormatVersion
			om.CryptoProThumbprint = hdr.ThumbprintHex()
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.body[key] = b
	m.meta[key] = om
	return nil
}

func (m *memStore) Get(_ context.Context, key string) (io.ReadCloser, domain.ObjectMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.body[key]
	if !ok {
		return nil, domain.ObjectMeta{}, domain.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(b)), m.meta[key], nil
}

func (m *memStore) GetRange(_ context.Context, key string, start, end int64) (io.ReadCloser, domain.ObjectMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.body[key]
	if !ok {
		return nil, domain.ObjectMeta{}, domain.ErrNotFound
	}
	if start < 0 || end < start {
		return nil, domain.ObjectMeta{}, fmt.Errorf("invalid range")
	}
	if start >= int64(len(b)) {
		return io.NopCloser(bytes.NewReader(nil)), m.meta[key], nil
	}
	to := end + 1
	if to > int64(len(b)) {
		to = int64(len(b))
	}
	return io.NopCloser(bytes.NewReader(b[start:to])), m.meta[key], nil
}

func TestListenIsLoopback(t *testing.T) {
	t.Parallel()
	assert.True(t, httpserver.ListenIsLoopback("127.0.0.1:8080"))
	assert.True(t, httpserver.ListenIsLoopback("[::1]:8080"))
	assert.True(t, httpserver.ListenIsLoopback("localhost:8080"))
	assert.False(t, httpserver.ListenIsLoopback("0.0.0.0:8080"))
	assert.False(t, httpserver.ListenIsLoopback(":8080"))
}

func TestNewRejectsOpenListenWithoutToken(t *testing.T) {
	t.Parallel()
	_, err := httpserver.New(httpserver.Config{
		Listen: "0.0.0.0:8080",
		Fetch:  service.NewFetch(newMemStore(), encrypt.Passthrough{}),
		Store:  newMemStore(),
	})
	require.ErrorIs(t, err, httpserver.ErrTokenRequired)
}

func TestServeFileAndRange(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	payload := []byte("abcdefghij")
	sum := sha256.Sum256(payload)
	hdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: int64(len(payload)),
		SHA256:        sum[:],
		Enc:           container.EncNone,
	})
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), "backups/hello.txt",
		io.MultiReader(bytes.NewReader(hdr), bytes.NewReader(payload)), domain.PutMeta{}))
	disk, err := cache.New(cache.Options{Dir: t.TempDir(), TTL: time.Hour, MaxBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })

	fetch := service.NewFetch(store, encrypt.Passthrough{}).WithCache(disk, "bucket", "fp")
	srv, err := httpserver.New(httpserver.Config{
		Listen: "127.0.0.1:0",
		Fetch:  fetch,
		Keys:   keying.Mapper{Prefix: "backups"},
		Store:  store,
	})
	require.NoError(t, err)

	wantETag := `"` + hex.EncodeToString(sum[:]) + `"`
	req := httptest.NewRequest(http.MethodGet, "/files/hello.txt", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, payload, rec.Body.Bytes())
	assert.Equal(t, wantETag, rec.Header().Get("ETag"))

	req = httptest.NewRequest(http.MethodGet, "/files/hello.txt", nil)
	req.Header.Set("Range", "bytes=2-5")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusPartialContent, rec.Code)
	assert.Equal(t, []byte("cdef"), rec.Body.Bytes())
}

func TestServeNotFoundAndTraversal(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	disk, err := cache.New(cache.Options{Dir: t.TempDir(), TTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })
	srv, err := httpserver.New(httpserver.Config{
		Listen: "127.0.0.1:0",
		Fetch:  service.NewFetch(store, encrypt.Passthrough{}).WithCache(disk, "b", "fp"),
		Keys:   keying.Mapper{Prefix: "backups"},
		Store:  store,
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/files/missing.txt", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/files/foo/%2e%2e/%2e%2e/etc/passwd", nil)
	srv.Handler().ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusOK, rec.Code)
	assert.NotEqual(t, http.StatusPartialContent, rec.Code)
}

func TestBearerAuth(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	disk, err := cache.New(cache.Options{Dir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })
	srv, err := httpserver.New(httpserver.Config{
		Listen: "127.0.0.1:0",
		Token:  "s3cret",
		Fetch:  service.NewFetch(store, encrypt.Passthrough{}).WithCache(disk, "b", "fp"),
		Store:  store,
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	assert.Equal(t, http.StatusOK, rec.Code)

	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
