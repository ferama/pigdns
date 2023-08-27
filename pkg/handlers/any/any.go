package any

import (
	"context"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
)

const (
	handlerName = "discard-any"
)

type Handler struct {
	Next pigdns.Handler
}

func (h *Handler) ServeDNS(c context.Context, r *pigdns.Request) {
	if c.Value(collector.CollectorContextKey) != nil {
		cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
		cc.AnweredBy = handlerName
	}
	if r.QType() == dns.TypeANY {
		res := new(dns.Msg)
		res.RecursionAvailable = false
		res.Authoritative = false
		r.ReplyWithStatus(res, dns.RcodeNotImplemented)
		return
	}

	h.Next.ServeDNS(c, r)
}
