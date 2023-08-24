package resolver

import (
	"context"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/recursor"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

type contextKey string

const ResolverContextKey contextKey = "resolver-middleware-context"

type ResolverContext struct {
	RecursionCount int
}

const (
	// retries until error
	maxRetriesOnError = 1

	// for logging
	handlerName = "resolver"
)

type handler struct {
	Next pigdns.Handler

	recursor    *recursor.Recursor
	allowedNets []string
}

func NewResolver(next pigdns.Handler, datadir string, allowedNets []string) *handler {
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
		log.Printf("[resolver] client '%s' is not allowed", r.ResponseWriter.RemoteAddr())
		h.Next.ServeDNS(c, r)
		return
	}

	m := new(dns.Msg)
	retries := maxRetriesOnError
	for {
		m, err = h.recursor.Query(c, r.Msg, r.FamilyIsIPv6())
		if err == nil {
			break
		}
		retries--

		if retries == 0 {
			log.Err(err).
				Str("query", r.Name()).
				Msg("resolver error")

			h.Next.ServeDNS(c, r)
			return
		}
	}
	if len(m.Answer) != 0 {
		cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
		cc.AnweredBy = handlerName
		m.Rcode = dns.RcodeSuccess
		m.RecursionAvailable = true
		r.Reply(m)
		return
	}

	h.Next.ServeDNS(c, r)
}
