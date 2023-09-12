package recursor

import (
	"context"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/recursor"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/rs/zerolog/log"
)

type contextKey string

const RecursorContextKey contextKey = "recursor-middleware-context"

type RecursorContext struct {
	RecursionCount int
}

const (
	// for logging
	handlerName = "recursor"
)

type handler struct {
	Next pigdns.Handler

	recursor    *recursor.Recursor
	allowedNets []string
}

func NewRecursor(next pigdns.Handler, datadir string, allowedNets []string) *handler {
	h := &handler{
		Next:        next,
		recursor:    recursor.New(datadir),
		allowedNets: allowedNets,
	}
	return h
}

func (h *handler) ServeDNS(c context.Context, r *pigdns.Request) {
	allowed, err := utils.IsClientAllowed(r.ResponseWriter.RemoteAddr(), h.allowedNets)
	if err != nil {
		log.Fatal().Err(err)
	}
	if !allowed {
		log.Printf("[recursor handler] client '%s' is not allowed", r.ResponseWriter.RemoteAddr())
		h.Next.ServeDNS(c, r)
		return
	}

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
