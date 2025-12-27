package api_key

import (
	"github.com/prometheus/client_golang/prometheus"
	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
)

const (
	MetricCreatedTotal = "created_total"
	MetricDeletedTotal = "deleted_total"
	MetricDuration     = "operation_duration_seconds"
)

const (
	LabelOpCreate   = "create"
	LabelOpDelete   = "delete"
	LabelOpValidate = "validate"
)

var (
	CreatedTotal *prometheus.CounterVec
	DeletedTotal *prometheus.CounterVec
	Duration     *prometheus.HistogramVec
	Errors       *prometheus.CounterVec
)

func init() {
	CreatedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      MetricCreatedTotal,
			Subsystem: pluginCore.API_KEY_SERVICE,
			Help:      "Total number of API keys created",
		},
		[]string{},
	)

	DeletedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      MetricDeletedTotal,
			Subsystem: pluginCore.API_KEY_SERVICE,
			Help:      "Total number of API keys deleted",
		},
		[]string{},
	)

	Duration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:      MetricDuration,
			Subsystem: pluginCore.API_KEY_SERVICE,
			Help:      "Duration of API key service operations",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"operation"},
	)

	Errors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      "errors_total",
			Subsystem: pluginCore.API_KEY_SERVICE,
			Help:      "Total number of API key service errors",
		},
		[]string{"operation"},
	)
}

func GetCollectors() []prometheus.Collector {
	return []prometheus.Collector{CreatedTotal, DeletedTotal, Duration}
}
