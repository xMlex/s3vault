package metrics_test

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/metrics"
)

func TestCollectorRecords(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	c, err := metrics.New(reg)
	require.NoError(t, err)

	c.File(metrics.OpArchive, metrics.ResultFound)
	c.File(metrics.OpArchive, metrics.ResultUploaded)
	c.AddBytes(metrics.DirUpload, 64)
	c.ObserveUpload(50*time.Millisecond, 64)
	c.CacheHit()
	c.CacheMiss()
	c.ObserveDownload(10*time.Millisecond, 32)
	c.AddBytes(metrics.DirDownload, 32)
	c.File(metrics.OpDownload, metrics.ResultDownloaded)

	require.NoError(t, c.RegisterCacheUsage(func() (int, int64, error) {
		return 3, 1024, nil
	}))

	mfs, err := reg.Gather()
	require.NoError(t, err)
	names := make(map[string]struct{}, len(mfs))
	for _, mf := range mfs {
		names[mf.GetName()] = struct{}{}
	}
	for _, want := range []string{
		"s3vault_files_total",
		"s3vault_bytes_total",
		"s3vault_upload_duration_seconds",
		"s3vault_download_duration_seconds",
		"s3vault_upload_size_bytes",
		"s3vault_download_size_bytes",
		"s3vault_cache_hits_total",
		"s3vault_cache_misses_total",
		"s3vault_cache_entries",
		"s3vault_cache_bytes",
	} {
		_, ok := names[want]
		assert.True(t, ok, "missing metric %s", want)
	}
}

func TestNilCollectorIsNoop(t *testing.T) {
	t.Parallel()
	var c *metrics.Collector
	c.File(metrics.OpUpload, metrics.ResultFailed)
	c.AddBytes(metrics.DirUpload, 1)
	c.ObserveUpload(time.Second, 1)
	c.ObserveDownload(time.Second, 1)
	c.CacheHit()
	c.CacheMiss()
	assert.Nil(t, c.Gatherer())
}
