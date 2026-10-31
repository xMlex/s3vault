package httpserver_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/httpserver"
)

func TestReadyCheck(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	srv, err := httpserver.New(httpserver.Config{
		Store:     store,
		S3Handler: handler,
		ReadyCheck: func(context.Context) error {
			return errors.New("auth database down")
		},
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ready", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	srv, err = httpserver.New(httpserver.Config{
		Store:      store,
		S3Handler:  handler,
		ReadyCheck: func(context.Context) error { return nil },
	})
	require.NoError(t, err)

	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ready", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
}
