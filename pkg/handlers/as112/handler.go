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

	qname := strings.ToLower(r.QName())

	msg := new(dns.Msg)
	// msg.SetReply(req)
	msg.Authoritative = true
	msg.RecursionAvailable = true

	soaHeader := dns.RR_Header{
		Name:   r.Name(),
		Rrtype: dns.TypeSOA,
		Class:  dns.ClassINET,
		Ttl:    86400,
	}
	soa := &dns.SOA{
		Hdr:     soaHeader,
		Ns:      zone,
		Mbox:    ".",
		Serial:  0,
		Refresh: 28800,
		Retry:   7200,
		Expire:  604800,
		Minttl:  86400,
	}

	switch r.QType() {
	case dns.TypeNS:
		if zone == qname {
			nsHeader := dns.RR_Header{
				Name:   r.QName(),
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    0,
			}
			ns := &dns.NS{
				Hdr: nsHeader,
				Ns:  zone,
			}
			msg.Answer = append(msg.Answer, ns)
		} else {
			msg.Ns = append(msg.Ns, soa)
		}
	case dns.TypeSOA:
		if zone == qname {
			msg.Answer = append(msg.Answer, soa)
		} else {
			msg.Ns = append(msg.Ns, soa)
		}
	default:
		msg.Ns = append(msg.Ns, soa)
	}

	if zone != qname {
		msg.Rcode = dns.RcodeNameError
	}

	r.Reply(msg)

	// h.Next.ServeDNS(c, r)
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
