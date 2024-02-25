package proxy

import (
	"context"
	"strings"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/racer"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

const (
	// for logging
	handlerName = "proxy"
)

type handler struct {
	Next pigdns.Handler

	servers []racer.NS

	racer *racer.QueryRacer
}

func NewProxyHandler(next pigdns.Handler, upstream []string, qr *racer.QueryRacer) *handler {

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
		Next:    next,
		servers: servers,
		racer:   qr,
	}

	return h
}

func (h *handler) ServeDNS(c context.Context, r *pigdns.Request) {
	r.Msg.RecursionDesired = true
	m, err := h.racer.Run(h.servers, r.Msg, r.FamilyIsIPv6())
	if err != nil {
		log.Error().
			Str("query", r.Name()).
			Str("type", r.Type()).
			Str("err", err.Error()).
			Msg("proxy error")

		h.Next.ServeDNS(c, r)
		return
	}

	pc := c.Value(pigdns.PigContextKey).(*pigdns.PigContext)
	pc.Rcode = m.Rcode

	if m.Rcode != dns.RcodeSuccess {
		log.Error().
			Str("query", r.Name()).
			Str("type", r.Type()).
			Str("rcode", dns.RcodeToString[m.Rcode]).
			Msg("query error")
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

		m = utils.MsgCleanup(m, r.Msg)
		r.ReplyWithStatus(m, m.Rcode)
		return
	}

	h.Next.ServeDNS(c, r)
}
