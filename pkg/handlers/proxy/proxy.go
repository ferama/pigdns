package proxy

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/metrics"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/racer"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

const (
	// for logging
	handlerName = "proxy"

	ansCacheName = "anscache"
)

type handler struct {
	Next pigdns.Handler

	ansCache *ansCache
	servers  []racer.NS
}

func NewProxyHandler(next pigdns.Handler, upstream []string, cacheSize int, datadir string) *handler {

	servers := make([]racer.NS, 0)
	for _, u := range upstream {
		if strings.Contains(u, "::") {
			servers = append(servers, racer.NS{
				Addr:    u,
				Version: pigdns.FamilyIPv6,
			})
		} else {
			servers = append(servers, racer.NS{
				Addr:    u,
				Version: pigdns.FamilyIPv4,
			})
		}
	}

	h := &handler{
		Next:     next,
		ansCache: newAnsCache(filepath.Join(datadir, "cache", "proxy"), ansCacheName, cacheSize),
		servers:  servers,
	}

	metrics.Instance().RegisterCache(ansCacheName)

	return h
}

func (h *handler) ServeDNS(c context.Context, r *pigdns.Request) {

	q := r.Msg.Question[0]
	reqKey := fmt.Sprintf("%s_%d_%d", q.Name, q.Qtype, q.Qclass)

	m, cacheErr := h.ansCache.Get(reqKey)
	if cacheErr == nil {
		pc := c.Value(pigdns.PigContextKey).(*pigdns.PigContext)
		pc.CacheHit = true
	} else {
		qr := racer.NewQueryRacer(h.servers, r.Msg, r.FamilyIsIPv6())
		qr.RecursionDesired = true

		var err error
		m, err = qr.Run()
		if err != nil {
			log.Error().
				Str("query", r.Name()).
				Str("type", r.Type()).
				Str("err", err.Error()).
				Msg("proxy error")

			h.Next.ServeDNS(c, r)
			return
		}
		h.ansCache.Set(reqKey, m)
	}

	pc := c.Value(pigdns.PigContextKey).(*pigdns.PigContext)
	pc.Rcode = m.Rcode

	if m.Rcode != dns.RcodeSuccess {
		log.Error().
			Str("query", r.Name()).
			Str("type", r.Type()).
			Str("rcode", dns.RcodeToString[m.Rcode]).
			Msg("query error")
		r.ReplyWithStatus(m, m.Rcode)
		return
	}

	if len(m.Answer) != 0 || len(m.Ns) != 0 {
		cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
		cc.AnweredBy = handlerName
		m.Authoritative = false
		utils.MsgSetupEdns(m)

		// set the do flag
		if r.IsDo() {
			utils.MsgSetDo(m, true)
		}

		r.ReplyWithStatus(m, m.Rcode)
		return
	}

	h.Next.ServeDNS(c, r)
}
