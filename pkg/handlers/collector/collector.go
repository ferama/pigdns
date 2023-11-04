package collector

import (
	"context"
	"time"

	"github.com/ferama/pigdns/pkg/metrics"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type contextKey string

const CollectorContextKey contextKey = "collector-middleware-context"

type CollectorContext struct {
	StartTime time.Time
	AnweredBy string
}

type Handler struct {
	Next pigdns.Handler
}

func (h *Handler) emitLogs(c context.Context, r *pigdns.Request) {
	cc := c.Value(CollectorContextKey).(*CollectorContext)
	totalLatency := time.Since(cc.StartTime)

	isDOH := false
	cacheHit := false
	rcode := 0
	if c.Value(pigdns.PigContextKey) != nil {
		pc := c.Value(pigdns.PigContextKey).(*pigdns.PigContext)

		if pc.Internal {
			// do not log internal requests
			return
		}
		isDOH = pc.IsDOH
		cacheHit = pc.CacheHit
		rcode = pc.Rcode
	}

	isDOHproxy := cc.AnweredBy == "doh-proxy"

	var event *zerolog.Event

	if isDOHproxy {
		event = log.Info().
			Str("query", r.Name()).
			Str("type", r.Type()).
			Str("latency", totalLatency.Round(1*time.Millisecond).String()).
			Str("protocol", r.Proto())
	} else {
		event = log.Info().
			Str("query", r.Name()).
			Str("type", r.Type()).
			Float64("latency", totalLatency.Seconds()).
			Str("latencyHuman", totalLatency.Round(1*time.Millisecond).String()).
			Str("protocol", r.Proto()).
			Bool("isDOH", isDOH).
			Bool("cached", cacheHit).
			Str("handler", cc.AnweredBy).
			Str("rcode", dns.RcodeToString[rcode]).
			Str("client", r.IP())
	}

	event.Send()

	metrics.Instance().QueryLatency.Observe(totalLatency.Seconds())
	metrics.Instance().CounterByRcode[rcode].Inc()

	if cacheHit {
		metrics.Instance().QueryCacheHit()
	} else {
		metrics.Instance().QueryCacheMiss()
	}
}

func (h *Handler) ServeDNS(c context.Context, r *pigdns.Request) {
	cc := &CollectorContext{
		StartTime: time.Now(),
	}
	c = context.WithValue(c, CollectorContextKey, cc)
	defer h.emitLogs(c, r)

	h.Next.ServeDNS(c, r)
}
