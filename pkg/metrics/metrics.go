package metrics

import (
	"sync"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	once     sync.Once
	instance *metrics
)

func Instance() *metrics {
	once.Do(func() {
		instance = newMetrics()
	})

	return instance
}

type metrics struct {
	CounterByRcode map[int]prometheus.Counter

	QueriesProcessedNoCache  prometheus.Counter
	QueriesProcessedCacheHit prometheus.Counter

	QueryLatency prometheus.Histogram
}

func newMetrics() *metrics {
	m := &metrics{
		CounterByRcode: make(map[int]prometheus.Counter),

		QueriesProcessedNoCache: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "pigdns_processed_total",
			Help:        "The total number of processed events",
			ConstLabels: prometheus.Labels{"cache": "hit"},
		}),

		QueriesProcessedCacheHit: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "pigdns_processed_total",
			Help:        "The total number of processed events",
			ConstLabels: prometheus.Labels{"cache": "miss"},
		}),

		QueryLatency: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "pigdns_latency",
			Help:    "Request latency",
			Buckets: []float64{0.2, 0.5, 3},
		}),
	}

	m.rcodeMetrics()
	return m
}

func (m *metrics) rcodeMetrics() {
	for k, r := range dns.RcodeToString {
		m.CounterByRcode[k] = promauto.NewCounter(prometheus.CounterOpts{
			Name:        "pigdns_rcode_counter",
			Help:        "Counter by rcode",
			ConstLabels: prometheus.Labels{"rcode": r},
		})
	}
}
