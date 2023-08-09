package root

import (
	"context"
	"fmt"
	"log"

	"github.com/ferama/pigdns/pkg/handlers/zone"
	"github.com/miekg/dns"
)

type Handler struct {
}

func (h *Handler) ServeDNS(c context.Context, w dns.ResponseWriter, r *dns.Msg) {
	logMsg := ""
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Rcode = dns.RcodeSuccess

	for _, q := range m.Question {
		logMsg = fmt.Sprintf("%s[root] query=%s", logMsg, q.String())
	}

	if r.Opcode != dns.OpcodeQuery {
		return
	}

	rr := zone.GetSOArecord()
	m.Answer = append(m.Answer, rr)

	logMsg = fmt.Sprintf("%s answer=%s", logMsg, rr)
	log.Println(logMsg)

	w.WriteMsg(m)
}
