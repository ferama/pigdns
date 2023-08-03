package zone

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

type Handler struct {
	Next dns.Handler

	domain string
	origin string
}

func New(next dns.Handler) dns.Handler {
	domain := viper.GetString("domain")

	h := &Handler{
		Next:   next,
		domain: domain,
		origin: fmt.Sprintf("%s.", domain),
	}

	return h
}

func (h *Handler) handleRecord(m *dns.Msg, record dns.RR, q dns.Question) string {
	logMsg := ""
	rname := strings.ToLower(record.Header().Name)
	qname := strings.ToLower(q.Name)

	// record with empty name. append origin
	if rname == "" {
		rname = h.origin
		record.Header().Name = h.origin
	}

	// not asking for current record. return
	if rname != qname {
		return logMsg
	}

	// handle special cases
	if record.Header().Rrtype != q.Qtype {
		switch record.Header().Rrtype {
		case dns.TypeCNAME:
			if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
				return logMsg
			}

			cname := record.(*dns.CNAME)

			// try find query target record
			rmsg := new(dns.Msg)
			rmsg.SetQuestion(cname.Target, q.Qtype)
			alog := h.handleQuery(rmsg)
			if len(rmsg.Answer) != 0 {
				log.Println(alog)
				m.Answer = append(m.Answer, rmsg.Answer...)
			}

			if len(m.Answer) == 0 {
				return logMsg
			}
		default:
			return logMsg
		}
	}

	m.Answer = append(m.Answer, record)
	logMsg = fmt.Sprintf("%s answer=%s", logMsg, record)

	return logMsg
}

func (h *Handler) handleQuery(m *dns.Msg) string {
	records := ZoneFileInst().GetRecords()

	logMsg := ""
	for _, q := range m.Question {
		logMsg = fmt.Sprintf("%s[zone] query=%s", logMsg, q.String())
		for _, record := range records {
			rlog := ""
			rlog = h.handleRecord(m, record, q)
			logMsg = fmt.Sprintf("%s%s", logMsg, rlog)
		}
	}
	if len(m.Answer) == 0 {
		logMsg = fmt.Sprintf("%s answer=no-answer", logMsg)
		return logMsg
	}
	return logMsg
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	logMsg := ""

	switch r.Opcode {
	case dns.OpcodeQuery:
		logMsg = h.handleQuery(m)
	}

	log.Println(logMsg)
	if len(m.Answer) != 0 {
		m.Rcode = dns.RcodeSuccess
		w.WriteMsg(m)
		return
	}

	h.Next.ServeDNS(w, r)
}
