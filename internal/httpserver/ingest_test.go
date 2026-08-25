package httpserver_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/cache"
	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/adapter/remote"
	"github.com/xMlex/s3vault/internal/adapter/scanner"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/httpserver"
	"github.com/xMlex/s3vault/internal/identity"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/service"
)

func TestIngestPutUploadSkipConflict(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	disk, err := cache.New(cache.Options{Dir: t.TempDir(), TTL: time.Hour, MaxBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })

	keys := keying.Mapper{Prefix: "backups"}
	arch := service.NewArchive(scanner.New(scanner.Options{}), keys, store, encrypt.Passthrough{}, nil)
	fetch := service.NewFetch(store, encrypt.Passthrough{}).WithCache(disk, "bucket", "fp")
	srv, err := httpserver.New(httpserver.Config{
		Listen:   "127.0.0.1:0",
		Token:    "tok",
		Fetch:    fetch,
		Archive:  arch,
		OnChange: identity.OnChangeFail,
		Keys:     keys,
		Store:    store,
	})
	require.NoError(t, err)

	payload := []byte("hello-ingest")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])

	req := httptest.NewRequest(http.MethodPut, "/files/logs/a.log", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("X-S3Vault-Mtime", time.Unix(1_700_000_000, 0).UTC().Format(time.RFC3339))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusCreated, rec.Code)

	meta, err := store.Head(context.Background(), "backups/logs/a.log")
	require.NoError(t, err)
	assert.True(t, meta.Exists)
	assert.Equal(t, hexSum, meta.SHA256)
	body := store.body["backups/logs/a.log"]
	require.True(t, container.IsMagic(body))
	assert.Equal(t, payload, body[container.HeaderSize:])

	req = httptest.NewRequest(http.MethodPut, "/files/logs/a.log", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	other := []byte("other-content")
	req = httptest.NewRequest(http.MethodPut, "/files/logs/a.log", bytes.NewReader(other))
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestIngestRequiresAuthAndArchive(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	disk, err := cache.New(cache.Options{Dir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })

	srv, err := httpserver.New(httpserver.Config{
		Listen: "127.0.0.1:0",
		Token:  "tok",
		Fetch:  service.NewFetch(store, encrypt.Passthrough{}).WithCache(disk, "b", "fp"),
		Store:  store,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/files/x.log", bytes.NewReader([]byte("x")))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	req = httptest.NewRequest(http.MethodPut, "/files/x.log", bytes.NewReader([]byte("x")))
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

func TestArchiveRemoteRoundTrip(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	disk, err := cache.New(cache.Options{Dir: t.TempDir(), TTL: time.Hour, MaxBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })

	keys := keying.Mapper{Prefix: "backups"}
	serverArch := service.NewArchive(scanner.New(scanner.Options{}), keying.Mapper{}, store, encrypt.Passthrough{}, nil)
	srv, err := httpserver.New(httpserver.Config{
		Listen:  "127.0.0.1:0",
		Token:   "tok",
		Fetch:   service.NewFetch(store, encrypt.Passthrough{}).WithCache(disk, "b", "fp"),
		Archive: serverArch,
		Keys:    keying.Mapper{}, // empty: client --prefix becomes the object key prefix
		Store:   store,
	})
	require.NoError(t, err)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	rc, err := remote.New(remote.Options{
		BaseURL:      ts.URL,
		Token:        "tok",
		RateLimitBPS: 1 << 20,
		HTTPClient:   ts.Client(),
	})
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "f.log")
	require.NoError(t, os.WriteFile(path, []byte("via-remote"), 0o600))
	st, err := os.Stat(path)
	require.NoError(t, err)

	clientArch := service.NewArchive(scanner.New(scanner.Options{}), keys, nil, encrypt.Passthrough{}, nil).WithRemote(rc)
	stats, _, err := clientArch.UploadFile(context.Background(), domain.FileInfo{
		AbsPath: path,
		RelPath: "f.log",
		Size:    st.Size(),
		ModTime: st.ModTime(),
	}, service.ArchiveOptions{Root: dir})
	require.NoError(t, err)
	assert.Equal(t, 1, stats.Uploaded)

	meta, err := store.Head(context.Background(), "backups/f.log")
	require.NoError(t, err)
	assert.True(t, meta.Exists)
	body := store.body["backups/f.log"]
	require.True(t, container.IsMagic(body))
	assert.Equal(t, []byte("via-remote"), body[container.HeaderSize:])
}
