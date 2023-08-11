package acmec

import (
	"context"
	"fmt"
	"regexp"

	"github.com/rs/zerolog/log"

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

func (h *Handler) parseQuery(m *dns.Msg, r *pigdns.Request) {
	token := certman.Token()
	if token.Get() == "" {
		return
	}

	log.Printf("[acmec] query for %s\n", r.Name())

	switch r.QType() {
	case dns.TypeTXT:
		if !dns01ChallengeRE.MatchString(r.Name()) {
			return
		}
	default:
		return
	}

	rr, err := dns.NewRR(fmt.Sprintf("%s TXT %s", r.Name(), token.Get()))
	rr.Header().Ttl = 120 // seconds
	if err == nil {
		m.Answer = append(m.Answer, rr)
	} else {
		log.Printf("%s", err)
	}
}

func (h *Handler) ServeDNS(c context.Context, r *pigdns.Request) {
	m := new(dns.Msg)
	m.Authoritative = true

	switch r.Msg.Opcode {
	case dns.OpcodeQuery:
		h.parseQuery(m, r)
	}

	if len(m.Answer) != 0 {
		m.Rcode = dns.RcodeSuccess
		r.Reply(m)
		return
	}

	h.Next.ServeDNS(c, r)
}
