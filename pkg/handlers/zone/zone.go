package zone

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
)

const handlerName = "zone"

type Handler struct {
	Next pigdns.Handler

	domain   string
	zoneFile string
	origin   string
}

func New(next pigdns.Handler, domain string, zoneFile string) pigdns.Handler {
	h := &Handler{
		Next:     next,
		domain:   domain,
		zoneFile: zoneFile,
		origin:   fmt.Sprintf("%s.", domain),
	}

	return h
}

func (h *Handler) handleRecord(m *dns.Msg, record dns.RR, r *pigdns.Request) string {
	logMsg := ""
	rname := strings.ToLower(record.Header().Name)
	qname := r.Name()

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
	if record.Header().Rrtype != r.QType() {
		switch record.Header().Rrtype {
		case dns.TypeCNAME:
			if r.QType() != dns.TypeA && r.QType() != dns.TypeAAAA {
				return logMsg
			}

			cname := record.(*dns.CNAME)

			// try find query target record
			rmsg := new(dns.Msg)
			newr := r.NewWithQuestion(cname.Target, r.QType())
			alog := h.handleQuery(rmsg, newr)
			if len(rmsg.Answer) != 0 {
				log.Print(alog)
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

func (h *Handler) handleQuery(m *dns.Msg, r *pigdns.Request) string {
	records := ZoneFileInst(h.zoneFile, h.domain).GetRecords()

	logMsg := ""
	logMsg = fmt.Sprintf("%s[zone] query=%s", logMsg, r.Name())
	for _, record := range records {
		rlog := ""
		rlog = h.handleRecord(m, record, r)
		logMsg = fmt.Sprintf("%s%s", logMsg, rlog)
	}
	if len(m.Answer) == 0 {
		logMsg = fmt.Sprintf("%s answer=no-answer", logMsg)
		return logMsg
	}
	return logMsg
}

func (h *Handler) ServeDNS(c context.Context, r *pigdns.Request) {
	m := new(dns.Msg)
	// m.SetReply(r.Msg)
	m.Authoritative = true

	logMsg := ""

	switch r.Msg.Opcode {
	case dns.OpcodeQuery:
		logMsg = h.handleQuery(m, r)
	}

	log.Print(logMsg)
	if len(m.Answer) != 0 {
		if c.Value(collector.CollectorContextKey) != nil {
			cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
			cc.AnweredBy = handlerName
		}
		m.Rcode = dns.RcodeSuccess
		r.Reply(m)
		return
	}

	h.Next.ServeDNS(c, r)
}
