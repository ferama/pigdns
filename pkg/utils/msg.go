package utils

import (
	"strings"

	"github.com/miekg/dns"
)

const (
	MaxTTL = 60 * 60 * 48 // 172800

	// https://www.netmeister.org/blog/dns-size.html
	MaxMsgSize = 1232
)

// MsgGetAnswerByType detects if an answer contains a message type.
// If yes returns it, else returns nil
// Usage:
//
//	do not filter by record name: MsgGetAnswerByType(m, dns.TypeA, "")
//	filter by record name: MsgGetAnswerByType(m, dns.TypeA, "google.com")
func MsgGetAnswerByType(msg *dns.Msg, typ uint16, name string) []dns.RR {
	ret := []dns.RR{}

	if msg == nil {
		return ret
	}
	if len(msg.Answer) == 0 {
		return ret
	}
	for _, rr := range msg.Answer {
		if name == "" {
			if rr.Header().Rrtype == typ {
				ret = append(ret, rr)
			}
		} else {
			if rr.Header().Rrtype == typ && strings.EqualFold(rr.Header().Name, name) {
				ret = append(ret, rr)
			}
		}

	}

	return ret
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

func RemoveOPT(msg *dns.Msg) *dns.Msg {
	extra := make([]dns.RR, len(msg.Extra))
	copy(extra, msg.Extra)

	msg.Extra = []dns.RR{}

	for _, rr := range extra {
		switch rr.(type) {
		case *dns.OPT:
			continue
		default:
			msg.Extra = append(msg.Extra, rr)
		}
	}

	return msg
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
