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
	mu sync.Mutex

	cacheSize     map[string]prometheus.Gauge
	cacheCapacity map[string]prometheus.Gauge

	CounterByRcode map[int]prometheus.Counter

	QueriesProcessedCacheHit  prometheus.Counter
	QueriesProcessedCacheMiss prometheus.Counter

	QueriesBlocked prometheus.Counter

	QueryLatency prometheus.Histogram
}

func newMetrics() *metrics {
	m := &metrics{
		CounterByRcode: make(map[int]prometheus.Counter),
		cacheSize:      make(map[string]prometheus.Gauge),
		cacheCapacity:  make(map[string]prometheus.Gauge),

		QueriesProcessedCacheHit: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "pigdns_processed_total",
			Help:        "The total number of processed events",
			ConstLabels: prometheus.Labels{"cache": "hit"},
		}),

		QueriesProcessedCacheMiss: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "pigdns_processed_total",
			Help:        "The total number of processed events",
			ConstLabels: prometheus.Labels{"cache": "miss"},
		}),

		QueriesBlocked: promauto.NewCounter(prometheus.CounterOpts{
			Name: "pigdns_blocked_counter",
			Help: "Total blocked queries",
		}),

		QueryLatency: promauto.NewHistogram(prometheus.HistogramOpts{
			Name: "pigdns_latency",
			Help: "Request latency",
		}),
	}

	m.rcodeMetrics()
	return m
}

func (m *metrics) RegisterCache(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cacheSize[name] = promauto.NewGauge(prometheus.GaugeOpts{
		Name:        "pigdns_cache_size",
		Help:        "Cache size in bytes",
		ConstLabels: prometheus.Labels{"cache": name},
	})

	m.cacheCapacity[name] = promauto.NewGauge(prometheus.GaugeOpts{
		Name:        "pigdns_cache_capacity",
		Help:        "Cache size in bytes",
		ConstLabels: prometheus.Labels{"cache": name},
	})
}

func (m *metrics) GetCacheSizeMetric(name string) prometheus.Gauge {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.cacheSize[name]; ok {
		return m.cacheSize[name]
	}
	return nil
}

func (m *metrics) GetCacheCapacityMetric(name string) prometheus.Gauge {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.cacheCapacity[name]; ok {
		return m.cacheCapacity[name]
	}
	return nil
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
