package utils

import (
	"github.com/miekg/dns"
)

const (
	MaxTTL     = 60 * 60 * 48 // 172800
	MaxMsgSize = 1232
)

// MsgGetAnswerByType detects if an answer contains a message type.
// If yes returns it, else returns nil
// Usage: MsgGetAnswerByType(m, dns.TypeA)
func MsgGetAnswerByType(msg *dns.Msg, typ uint16) dns.RR {
	if msg == nil {
		return nil
	}
	if len(msg.Answer) == 0 {
		return nil
	}
	for _, rr := range msg.Answer {
		switch typ {
		case dns.TypeA:
			if _, ok := rr.(*dns.A); ok {
				return rr
			}
		case dns.TypeAAAA:
			if _, ok := rr.(*dns.AAAA); ok {
				return rr
			}
		case dns.TypeCNAME:
			if _, ok := rr.(*dns.CNAME); ok {
				return rr
			}
		}

	}

	return nil
}

func MsgGetMinTTL(m *dns.Msg) uint32 {
	var minTTL uint32
	minTTL = MaxTTL
	for _, a := range m.Answer {
		ttl := a.Header().Ttl
		if ttl == 0 {
			continue
		}
		minTTL = min(minTTL, ttl)
	}
	for _, a := range m.Extra {
		ttl := a.Header().Ttl
		if ttl == 0 {
			continue
		}
		minTTL = min(minTTL, ttl)
	}

	return minTTL
}

func MsgSetupEdns(m *dns.Msg) {

	m.Compress = true

	if m.IsEdns0() == nil {
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(MaxMsgSize)

		m.Extra = append(m.Extra, opt)
	} else {
		opt := m.IsEdns0()
		opt.SetUDPSize(MaxMsgSize)
	}
	// log.Printf("####### len: %d", m.Len())
}
