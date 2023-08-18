package utils

import "github.com/miekg/dns"

// MsgGetAnswerByType detects if an answer contains a message type
// Usage: MsgGetAnswerByType(m, dns.TypeA)
func MsgGetAnswerByType(msg *dns.Msg, typ uint16) dns.RR {
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
