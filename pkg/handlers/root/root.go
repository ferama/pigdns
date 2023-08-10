package root

import (
	"context"
	"fmt"
	"log"

	"github.com/ferama/pigdns/pkg/handlers/zone"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
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

	logMsg = fmt.Sprintf("%s answer=%s", logMsg, rr)
	log.Println(logMsg)

	r.Reply(m)
}
