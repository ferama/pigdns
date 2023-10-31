package as112

import (
	"context"
	"strings"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
)

const (
	// refer to https://as112.net/
	handlerName = "as112"
)

type Handler struct {
	Next pigdns.Handler
}

func (h *Handler) ServeDNS(c context.Context, r *pigdns.Request) {
	if c.Value(collector.CollectorContextKey) != nil {
		cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
		cc.AnweredBy = handlerName
	}

	if !strings.HasSuffix(r.QName(), "arpa.") {
		h.Next.ServeDNS(c, r)
		return
	}

	zone := h.Match(r.Name(), r.QType())

	if zone == "." {
		h.Next.ServeDNS(c, r)
		return
	}

	msg := new(dns.Msg)
	msg.Authoritative = true
	msg.RecursionAvailable = true

	r.ReplyWithStatus(msg, dns.RcodeNameError)
}

func (h *Handler) Match(name string, qtype uint16) string {
	name = dns.CanonicalName(name)

	if qtype == dns.TypeDS {
		i, end := dns.NextLabel(name, 0)

		name = name[i:]
		if end {
			return "."
		}
	}

	i := 0
	end := false
	for {
		i, end = dns.NextLabel(name, i)
		if end {
			break
		}
		if _, ok := as112Zones[name[i:]]; ok {
			return name[i:]
		}
	}

	return "."
}
