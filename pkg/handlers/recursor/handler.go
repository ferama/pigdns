package recursor

import (
	"context"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/recursor"
	"github.com/ferama/pigdns/pkg/utils"
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

func NewRecursorHandler(next pigdns.Handler, datadir string, cacheSize int64) *handler {
	h := &handler{
		Next:     next,
		recursor: recursor.New(datadir, cacheSize),
	}
	return h
}

func (h *handler) ServeDNS(c context.Context, r *pigdns.Request) {
	m, err := h.recursor.Query(c, r.Msg, r.FamilyIsIPv6())
	if err != nil {
		log.Err(err).
			Str("query", r.Name()).
			Str("type", r.Type()).
			Msg("recursor error")

		h.Next.ServeDNS(c, r)
		return
	}

	if len(m.Answer) != 0 || len(m.Ns) != 0 {
		cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
		cc.AnweredBy = handlerName
		m.RecursionAvailable = true
		utils.MsgSetupEdns(m)

		r.ReplyWithStatus(m, m.Rcode)
		return
	}

	h.Next.ServeDNS(c, r)
}
