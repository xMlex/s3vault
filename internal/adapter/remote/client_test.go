package remote_test

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/remote"
)

func TestNewRejectsBadURL(t *testing.T) {
	t.Parallel()
	_, err := remote.New(remote.Options{BaseURL: ""})
	require.Error(t, err)
	_, err = remote.New(remote.Options{BaseURL: "ftp://x"})
	require.Error(t, err)
}

func TestLimiterCapsThroughput(t *testing.T) {
	t.Parallel()
	lim := remote.NewLimiter(1024) // 1 KiB/s
	r := lim.Reader(context.Background(), bytes.NewReader(make([]byte, 2048)))
	started := time.Now()
	n, err := io.Copy(io.Discard, r)
	require.NoError(t, err)
	assert.Equal(t, int64(2048), n)
	elapsed := time.Since(started)
	assert.GreaterOrEqual(t, elapsed, 1500*time.Millisecond)
}
