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

// for tests that attempts to register metrics more than once
func Reset() {
	m := Instance()
	m.Lock()
	defer m.Unlock()

	for k, v := range m.cacheCapacity {
		prometheus.DefaultRegisterer.Unregister(v)
		delete(m.cacheCapacity, k)
	}

	for k, v := range m.cacheItems {
		prometheus.DefaultRegisterer.Unregister(v)
		delete(m.cacheItems, k)
	}

	for k, v := range m.CounterByRcode {
		prometheus.DefaultRegisterer.Unregister(v)
		delete(m.CounterByRcode, k)
	}

	prometheus.DefaultRegisterer.Unregister(m.queriesProcessedCacheHit)
	prometheus.DefaultRegisterer.Unregister(m.queriesProcessedCacheMiss)

	prometheus.DefaultRegisterer.Unregister(m.QueriesBlocked)
	prometheus.DefaultRegisterer.Unregister(m.QueryLatency)
}

type metrics struct {
	sync.RWMutex

	cacheCapacity map[string]prometheus.Gauge
	cacheItems    map[string]prometheus.Gauge

	CounterByRcode map[int]prometheus.Counter

	queriesProcessedCacheHit  prometheus.Counter
	queriesProcessedCacheMiss prometheus.Counter

	QueriesBlocked prometheus.Counter

	QueryLatency prometheus.Histogram
}

func newMetrics() *metrics {
	m := &metrics{
		CounterByRcode: make(map[int]prometheus.Counter),
		cacheCapacity:  make(map[string]prometheus.Gauge),
		cacheItems:     make(map[string]prometheus.Gauge),

		queriesProcessedCacheHit: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "pigdns_query_processed_total",
			Help:        "The total number of processed events",
			ConstLabels: prometheus.Labels{"cache": "hit"},
		}),

		queriesProcessedCacheMiss: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "pigdns_query_processed_total",
			Help:        "The total number of processed events",
			ConstLabels: prometheus.Labels{"cache": "miss"},
		}),

		QueriesBlocked: promauto.NewCounter(prometheus.CounterOpts{
			Name: "pigdns_query_blocked_total",
			Help: "Total blocked queries",
		}),

		QueryLatency: promauto.NewHistogram(prometheus.HistogramOpts{
			Name: "pigdns_query_latency",
			Help: "Request latency",
		}),
	}

	m.rcodeMetrics()
	return m
}

func (m *metrics) RegisterCache(name string) {
	m.Lock()
	defer m.Unlock()

	m.cacheCapacity[name] = promauto.NewGauge(prometheus.GaugeOpts{
		Name:        "pigdns_cache_capacity",
		Help:        "Cache max allowed items",
		ConstLabels: prometheus.Labels{"cache": name},
	})

	m.cacheItems[name] = promauto.NewGauge(prometheus.GaugeOpts{
		Name:        "pigdns_cached_items_count",
		Help:        "Cache items count",
		ConstLabels: prometheus.Labels{"cache": name},
	})
}

func (m *metrics) QueryCacheHit() {
	m.Lock()
	defer m.Unlock()

	m.queriesProcessedCacheHit.Inc()
}

func (m *metrics) QueryCacheMiss() {
	m.Lock()
	defer m.Unlock()

	m.queriesProcessedCacheMiss.Inc()
}

func (m *metrics) GetCacheCapacityMetric(name string) prometheus.Gauge {
	m.Lock()
	defer m.Unlock()

	if _, ok := m.cacheCapacity[name]; ok {
		return m.cacheCapacity[name]
	}
	return nil
}

func (m *metrics) GetCacheItemsCountMetric(name string) prometheus.Gauge {
	m.Lock()
	defer m.Unlock()

	if _, ok := m.cacheItems[name]; ok {
		return m.cacheItems[name]
	}
	return nil
}

func (m *metrics) rcodeMetrics() {
	for k, r := range dns.RcodeToString {
		m.CounterByRcode[k] = promauto.NewCounter(prometheus.CounterOpts{
			Name:        "pigdns_query_rcode_counter",
			Help:        "Counter by rcode",
			ConstLabels: prometheus.Labels{"rcode": r},
		})
	}
}
