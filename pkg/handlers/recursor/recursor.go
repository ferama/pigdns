package recursor

import (
	"context"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/racer"
	"github.com/ferama/pigdns/pkg/recursor"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

const (
	// for logging
	handlerName = "recursor"
)

type handler struct {
	Next pigdns.Handler

	recursor *recursor.Recursor
}

func NewRecursorHandler(next pigdns.Handler, datadir string, cacheSize int, cachePersistence bool, qr *racer.QueryRacer) *handler {
	h := &handler{
		Next:     next,
		recursor: recursor.New(datadir, cacheSize, cachePersistence, qr),
	}
	return h
}

func (h *handler) ServeDNS(c context.Context, r *pigdns.Request) {
	m, err := h.recursor.Query(c, r.Msg, r.FamilyIsIPv6())
	if err != nil {
		log.Error().
			Str("query", r.Name()).
			Str("type", r.Type()).
			Str("err", err.Error()).
			Msg("recursor error")

		h.Next.ServeDNS(c, r)
		return
	}

	pc := c.Value(pigdns.PigContextKey).(*pigdns.PigContext)
	pc.Rcode = m.Rcode

	if m.Rcode != dns.RcodeSuccess {
		cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
		cc.AnweredBy = handlerName
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
