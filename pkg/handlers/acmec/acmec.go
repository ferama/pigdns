package acmec

import (
	"context"
	"fmt"
	"log"
	"regexp"

	"github.com/ferama/pigdns/pkg/certman"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
)

var (
	dns01ChallengeRE = regexp.MustCompile(`(?i)_acme-challenge\.`)
)

type Handler struct {
	Next pigdns.Handler
}

func (h *Handler) parseQuery(m *dns.Msg) {
	token := certman.Token()
	if token.Get() == "" {
		return
	}

	for _, q := range m.Question {
		log.Printf("[acmec] query for %s\n", q.Name)

		switch q.Qtype {
		case dns.TypeTXT:
			if !dns01ChallengeRE.MatchString(q.Name) {
				continue
			}
		default:
			continue
		}

		rr, err := dns.NewRR(fmt.Sprintf("%s TXT %s", q.Name, token.Get()))
		rr.Header().Ttl = 120 // seconds
		if err == nil {
			m.Answer = append(m.Answer, rr)
		} else {
			log.Println(err)
		}
	}
}

func (h *Handler) ServeDNS(c context.Context, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	switch r.Opcode {
	case dns.OpcodeQuery:
		h.parseQuery(m)
	}

	if len(m.Answer) != 0 {
		m.Rcode = dns.RcodeSuccess
		w.WriteMsg(m)
		return
	}

	h.Next.ServeDNS(c, w, r)
}
