package utils

import (
	"strings"

	"github.com/miekg/dns"
)

const (
	MaxTTL = 60 * 60 * 24 // 86400

	// https://www.netmeister.org/blog/dns-size.html
	MaxMsgSize = 1232
)

// MsgExtractRRByType detects if an answer contains a message type.
// If yes returns it, else returns nil
// Usage:
//
//	do not filter by record name: MsgExtractRRByType(m, dns.TypeA, "")
//	filter by record name: MsgExtractRRByType(m, dns.TypeA, "google.com")
func MsgExtractByType(msg *dns.Msg, typ uint16, name string) []dns.RR {
	ret := []dns.RR{}

	if msg == nil {
		return ret
	}
	if len(msg.Answer) == 0 && len(msg.Extra) == 0 && len(msg.Ns) == 0 {
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

	for _, rr := range msg.Extra {
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

	for _, rr := range msg.Ns {
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

func MsgSetAuthenticated(m *dns.Msg, auth bool) {

	m.AuthenticatedData = auth
}

func MsgSetDo(m *dns.Msg, do bool) {
	if m.IsEdns0() != nil {
		m.IsEdns0().SetDo(do)
	}
}

func MsgGetDo(m *dns.Msg) bool {
	if m.IsEdns0() != nil {
		return m.IsEdns0().Do()
	}
	return false
}

func MsgSetupEdns(m *dns.Msg) {
	RemoveOPT(m)

	m.Compress = true

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(MaxMsgSize)

	m.Extra = append(m.Extra, opt)
}

func IsArpa(name string) bool {
	return strings.HasSuffix(name, "in-addr.arpa.") || strings.HasSuffix(name, ".ip6.arpa")
}

func AnsIsError(ans *dns.Msg) bool {
	switch ans.Rcode {
	case dns.RcodeServerFailure:
		fallthrough
	case dns.RcodeRefused:
		return true
	default:
		return false
	}
}
