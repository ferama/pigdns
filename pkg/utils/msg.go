package utils

import (
	"strings"

	"github.com/miekg/dns"
)

const (
	MsgMaxTTL = 60 * 60 * 24 // 86400

	// min ttl for cached msgs
	MsgMinTTL = 15

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
	minTTL = MsgMaxTTL
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

	return max(minTTL, MsgMinTTL)
}

func MsgRemoveOPT(msg *dns.Msg) *dns.Msg {
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
	MsgRemoveOPT(m)

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

// MsgCleanup prepares the answer to be returned to the client
// exluding not requested records
func MsgCleanup(ans *dns.Msg, req *dns.Msg) *dns.Msg {
	q := req.Question[0]

	cleaned := ans.Copy()
	cleaned.Answer = []dns.RR{}
	cleaned.Ns = []dns.RR{}

	opt := req.IsEdns0()

	for _, rr := range ans.Answer {
		if opt != nil && opt.Do() {
			if rr.Header().Rrtype == dns.TypeRRSIG {
				cleaned.Answer = append(cleaned.Answer, rr)
				continue
			}
		}
		// exclude not requested answers (except if they contains CNAMEs)
		if rr.Header().Rrtype != dns.TypeCNAME && rr.Header().Rrtype != q.Qtype {
			continue
		}
		// exclude TypeNone from the final answer
		if rr.Header().Rrtype == dns.TypeNone {
			continue
		}

		cleaned.Answer = append(cleaned.Answer, rr)
	}
	for _, rr := range ans.Ns {
		if rr.Header().Rrtype == q.Qtype && rr.Header().Class == q.Qclass {
			cleaned.Ns = append(cleaned.Ns, rr)
			continue
		}
		if rr.Header().Rrtype == dns.TypeSOA {
			cleaned.Ns = append(cleaned.Ns, rr)
			continue
		}
		if opt != nil && opt.Do() {
			cleaned.Ns = append(cleaned.Ns, rr)
		}

	}
	return cleaned
}
