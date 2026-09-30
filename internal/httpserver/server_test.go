package httpserver_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/httpserver"
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

func (m *memStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.body, key)
	delete(m.meta, key)
	return nil
}

func (m *memStore) List(_ context.Context, opts domain.ListOptions) (domain.ListPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var contents []domain.ListObject
	for key, meta := range m.meta {
		if opts.Prefix != "" && !strings.HasPrefix(key, opts.Prefix) {
			continue
		}
		contents = append(contents, domain.ListObject{
			Key:          key,
			Size:         meta.Size,
			ETag:         meta.ETag,
			LastModified: meta.LastModified,
		})
	}
	return domain.ListPage{Contents: contents, KeyCount: int32(len(contents))}, nil
}

// s3Stub stands in for the required SigV4 S3 facade.
func s3Stub() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
}

func TestNewRequiresS3API(t *testing.T) {
	t.Parallel()
	_, err := httpserver.New(httpserver.Config{
		Listen: "127.0.0.1:0",
		Store:  newMemStore(),
	})
	require.ErrorIs(t, err, httpserver.ErrS3CredsRequired)
}

func TestHealthAndReady(t *testing.T) {
	t.Parallel()
	srv, err := httpserver.New(httpserver.Config{
		Listen:    "127.0.0.1:0",
		Store:     newMemStore(),
		S3Handler: s3Stub(),
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok\n", rec.Body.String())

	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ready", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok\n", rec.Body.String())
}

func TestNonReservedPathsGoToS3(t *testing.T) {
	t.Parallel()
	srv, err := httpserver.New(httpserver.Config{
		Listen:    "127.0.0.1:0",
		Store:     newMemStore(),
		S3Handler: s3Stub(),
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mybucket/key", nil))
	assert.Equal(t, http.StatusTeapot, rec.Code)
}
