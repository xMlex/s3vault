package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// CacheUsage returns current plaintext cache occupancy for gauges.
type CacheUsage func() (entries int, bytes int64, err error)

// RegisterCacheUsage adds occupancy gauges that sample usage on scrape.
//
// PromQL: s3vault_cache_bytes / s3vault_cache_entries
func (c *Collector) RegisterCacheUsage(usage CacheUsage) error {
	if c == nil || usage == nil || c.gatherer == nil {
		return nil
	}
	reg, ok := c.gatherer.(prometheus.Registerer)
	if !ok {
		return nil
	}

	entries := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "s3vault_cache_entries",
		Help: "Plaintext cache entry count",
	}, func() float64 {
		n, _, err := usage()
		if err != nil {
			return 0
		}
		return float64(n)
	})
	bytes := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "s3vault_cache_bytes",
		Help: "Plaintext cache size in bytes",
	}, func() float64 {
		_, n, err := usage()
		if err != nil {
			return 0
		}
		return float64(n)
	})
	if err := register(reg, entries); err != nil {
		return err
	}
	return register(reg, bytes)
}
