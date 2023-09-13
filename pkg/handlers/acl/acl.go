package acl

import (
	"context"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/utils"
)

const handlerName = "acl"

type Handler struct {
	Next pigdns.Handler

	AllowedNets []string
}

func (h *Handler) ServeDNS(c context.Context, r *pigdns.Request) {
	allowed, err := utils.IsClientAllowed(r.ResponseWriter.RemoteAddr(), h.AllowedNets)
	if err != nil {
		log.Fatal().Err(err)
	}
	if !allowed {
		log.Printf("[acl handler] client '%s' is not allowed", r.ResponseWriter.RemoteAddr())
		cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
		cc.AnweredBy = handlerName
		m := new(dns.Msg)
		r.ReplyWithStatus(m, dns.RcodeRefused)
		return
	}
	h.Next.ServeDNS(c, r)
}
