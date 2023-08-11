package root

import (
	"context"
	"fmt"

	"github.com/ferama/pigdns/pkg/handlers/zone"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

type Handler struct {
}

func (h *Handler) ServeDNS(c context.Context, r *pigdns.Request) {
	m := new(dns.Msg)
	m.Authoritative = true
	m.Rcode = dns.RcodeSuccess

	logMsg := fmt.Sprintf("[root] query=%s", r.Name())

	if r.Msg.Opcode != dns.OpcodeQuery {
		return
	}

	rr := zone.GetSOArecord()
	m.Answer = append(m.Answer, rr)

	log.Printf("%s answer=%s", logMsg, rr)

	r.Reply(m)
}
