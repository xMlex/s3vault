package metrics

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Low-cardinality label values. Never put paths, keys, or request IDs here.
const (
	OpArchive  = "archive"
	OpUpload   = "upload"
	OpDownload = "download"

	ResultFound      = "found"
	ResultUploaded   = "uploaded"
	ResultSkipped    = "skipped"
	ResultFailed     = "failed"
	ResultDownloaded = "downloaded"

	DirUpload   = "upload"
	DirDownload = "download"
)

var (
	transferBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300}
	sizeBuckets     = prometheus.ExponentialBuckets(1024, 4, 12) // 1KiB .. 4GiB
)

// Collector holds s3vault Prometheus metrics. A nil *Collector is a no-op.
type Collector struct {
	gatherer prometheus.Gatherer

	files        *prometheus.CounterVec
	bytes        *prometheus.CounterVec
	uploadDur    prometheus.Histogram
	downloadDur  prometheus.Histogram
	uploadSize   prometheus.Histogram
	downloadSize prometheus.Histogram
	cacheHits    prometheus.Counter
	cacheMisses  prometheus.Counter
	httpDur      *prometheus.HistogramVec
	httpCount    *prometheus.CounterVec
	httpInFlight prometheus.Gauge
	httpRespSize *prometheus.HistogramVec
	s3Requests   *prometheus.CounterVec
}

// New registers collectors on reg. A nil reg creates a private registry.
func New(reg prometheus.Registerer) (*Collector, error) {
	if reg == nil {
		r := prometheus.NewRegistry()
		reg = r
	}

	c := &Collector{
		files: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "s3vault_files_total",
			Help: "Files processed by result (found, uploaded, skipped, failed, downloaded)",
		}, []string{"op", "result"}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "s3vault_bytes_total",
			Help: "Plaintext bytes transferred to or from object storage",
		}, []string{"direction"}),
		uploadDur: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "s3vault_upload_duration_seconds",
			Help:    "Time to encrypt and Put one object",
			Buckets: transferBuckets,
		}),
		downloadDur: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "s3vault_download_duration_seconds",
			Help:    "Time to Get and decrypt one object (cache misses)",
			Buckets: transferBuckets,
		}),
		uploadSize: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "s3vault_upload_size_bytes",
			Help:    "Plaintext size of successfully uploaded objects",
			Buckets: sizeBuckets,
		}),
		downloadSize: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "s3vault_download_size_bytes",
			Help:    "Plaintext size of objects fetched from S3",
			Buckets: sizeBuckets,
		}),
		cacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "s3vault_cache_hits_total",
			Help: "Plaintext cache hits",
		}),
		cacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "s3vault_cache_misses_total",
			Help: "Plaintext cache misses",
		}),
		httpDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "s3vault_http_request_duration_seconds",
			Help:    "HTTP request latency (no path labels)",
			Buckets: prometheus.DefBuckets,
		}, []string{"code", "method"}),
		httpCount: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "s3vault_http_requests_total",
			Help: "HTTP requests by status code and method",
		}, []string{"code", "method"}),
		httpInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "s3vault_http_requests_in_flight",
			Help: "In-flight HTTP requests",
		}),
		httpRespSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "s3vault_http_response_size_bytes",
			Help:    "HTTP response body size (Range-aware)",
			Buckets: sizeBuckets,
		}, []string{"code", "method"}),
		s3Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "s3vault_s3_requests_total",
			Help: "S3 API gateway requests by operation and result",
		}, []string{"op", "result"}),
	}

	all := []prometheus.Collector{
		c.files, c.bytes,
		c.uploadDur, c.downloadDur, c.uploadSize, c.downloadSize,
		c.cacheHits, c.cacheMisses,
		c.httpDur, c.httpCount, c.httpInFlight, c.httpRespSize,
		c.s3Requests,
	}
	for _, col := range all {
		if err := register(reg, col); err != nil {
			return nil, err
		}
	}

	if g, ok := reg.(prometheus.Gatherer); ok {
		c.gatherer = g
	}
	return c, nil
}

func register(reg prometheus.Registerer, c prometheus.Collector) error {
	if err := reg.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			return nil
		}
		return fmt.Errorf("register metrics: %w", err)
	}
	return nil
}

// Gatherer is the registry used for /metrics, or nil if the registerer cannot gather.
func (c *Collector) Gatherer() prometheus.Gatherer {
	if c == nil {
		return nil
	}
	return c.gatherer
}

// Handler serves the Prometheus text exposition format.
func (c *Collector) Handler() http.Handler {
	if c == nil || c.gatherer == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(c.gatherer, promhttp.HandlerOpts{})
}

// InstrumentHTTP wraps h with request count, duration, in-flight, and response size.
func (c *Collector) InstrumentHTTP(h http.Handler) http.Handler {
	if c == nil {
		return h
	}
	return promhttp.InstrumentHandlerInFlight(c.httpInFlight,
		promhttp.InstrumentHandlerDuration(c.httpDur,
			promhttp.InstrumentHandlerCounter(c.httpCount,
				promhttp.InstrumentHandlerResponseSize(c.httpRespSize, h),
			),
		),
	)
}

// File increments s3vault_files_total.
// PromQL: sum(rate(s3vault_files_total{result="failed"}[5m]))
func (c *Collector) File(op, result string) {
	if c == nil {
		return
	}
	c.files.WithLabelValues(op, result).Inc()
}

// AddBytes increments s3vault_bytes_total.
// PromQL: sum(rate(s3vault_bytes_total{direction="upload"}[5m]))
func (c *Collector) AddBytes(direction string, n int64) {
	if c == nil || n <= 0 {
		return
	}
	c.bytes.WithLabelValues(direction).Add(float64(n))
}

// ObserveUpload records a successful object upload.
func (c *Collector) ObserveUpload(d time.Duration, size int64) {
	if c == nil {
		return
	}
	c.uploadDur.Observe(d.Seconds())
	if size > 0 {
		c.uploadSize.Observe(float64(size))
	}
}

// ObserveDownload records a Get+decrypt (not a cache hit).
func (c *Collector) ObserveDownload(d time.Duration, size int64) {
	if c == nil {
		return
	}
	c.downloadDur.Observe(d.Seconds())
	if size > 0 {
		c.downloadSize.Observe(float64(size))
	}
}

// CacheHit increments s3vault_cache_hits_total.
func (c *Collector) CacheHit() {
	if c == nil {
		return
	}
	c.cacheHits.Inc()
}

// CacheMiss increments s3vault_cache_misses_total.
func (c *Collector) CacheMiss() {
	if c == nil {
		return
	}
	c.cacheMisses.Inc()
}

// S3 increments s3vault_s3_requests_total.
//
// op: get|put|delete|list|head|head_bucket|list_buckets|create_multipart|upload_part|complete_multipart|abort_multipart|list_parts; result: ok|denied|not_found|error|…
func (c *Collector) S3(op, result string) {
	if c == nil {
		return
	}
	c.s3Requests.WithLabelValues(op, result).Inc()
}
