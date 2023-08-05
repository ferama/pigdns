package forward

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

var upstream = []string{
	// "1.1.1.1:53",
	"208.67.222.222:53",
	"208.67.220.220:53",
}

type Handler struct {
	Next dns.Handler
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.Authoritative = false

	logMsg := ""

	q := r.Question[0]
	logMsg = fmt.Sprintf("%s[forward] query=%s", logMsg, q.String())

	m.SetQuestion(q.Name, q.Qtype)
	resp, err := dns.Exchange(m, upstream[0])
	if err != nil {
		logMsg = fmt.Sprintf("%s %s", logMsg, err)
		log.Println(logMsg)
		h.Next.ServeDNS(w, r)
		return
	}

	m.SetReply(r)
	m.Answer = append(m.Answer, resp.Answer...)
	if len(m.Answer) != 0 {
		log.Println(logMsg)
		m.Rcode = dns.RcodeSuccess
		w.WriteMsg(m)
		return
	}

	h.Next.ServeDNS(w, r)
}
