package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// RegisterRuntime adds Go and process collectors (server /metrics only).
func RegisterRuntime(reg prometheus.Registerer) error {
	if reg == nil {
		return nil
	}
	if err := register(reg, collectors.NewGoCollector()); err != nil {
		return err
	}
	return register(reg, collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}
