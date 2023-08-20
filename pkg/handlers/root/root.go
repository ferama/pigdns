package root

import (
	"context"
	"fmt"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/handlers/zone"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

const handlerName = "root"

type Handler struct {
	Domain   string
	ZoneFile string
}

func (h *Handler) ServeDNS(c context.Context, r *pigdns.Request) {
	m := new(dns.Msg)
	m.Authoritative = true
	m.Rcode = dns.RcodeSuccess

	logMsg := fmt.Sprintf("[root] query=%s", r.Name())

	if r.Msg.Opcode != dns.OpcodeQuery {
		return
	}

	rr := zone.GetSOArecord(h.Domain, h.ZoneFile)
	m.Answer = append(m.Answer, rr)
	cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
	cc.AnweredBy = handlerName

	log.Printf("%s answer=%s", logMsg, rr)

	r.Reply(m)
}
