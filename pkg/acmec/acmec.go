package acmec

import (
	"fmt"
	"log"
	"regexp"

	"github.com/miekg/dns"
)

var (
	dns01ChallengeRE = regexp.MustCompile(`(?i)_acme-challenge\.`)
)

type Handler struct {
	Next dns.Handler
}

func (h *Handler) parseQuery(m *dns.Msg) *dns.Msg {
	haveAnswer := false

	token := Token()

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
		if token.Get() == "" {
			continue
		}

		rr, err := dns.NewRR(fmt.Sprintf("%s TXT %s", q.Name, token.Get()))
		// rr.Header().Ttl = 180 // seconds
		rr.Header().Ttl = 120 // seconds
		if err == nil {
			m.Answer = append(m.Answer, rr)
			haveAnswer = true
		} else {
			log.Println(err)
		}
	}

	if !haveAnswer {
		return nil
	}

	return m
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Rcode = dns.RcodeSuccess

	switch r.Opcode {
	case dns.OpcodeQuery:
		m = h.parseQuery(m)
	}

	if m != nil {

		w.WriteMsg(m)
		return
	}

	h.Next.ServeDNS(w, r)
}
