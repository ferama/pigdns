package zone

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const confPollInterval = 5 * time.Second

type Handler struct {
	Next dns.Handler

	zoneFile string
	domain   string
	origin   string

	records []dns.RR

	cachedZoneFileModTime time.Time

	wg sync.WaitGroup
}

func New(next dns.Handler, domain string, zoneFile string) dns.Handler {
	h := &Handler{
		Next:     next,
		records:  make([]dns.RR, 0),
		zoneFile: zoneFile,
		domain:   domain,
		origin:   fmt.Sprintf("%s.", domain),
	}

	go h.watchConfig()

	return h
}

func (h *Handler) loadZonefile() {
	h.wg.Add(1)
	defer h.wg.Done()

	h.records = make([]dns.RR, 0)

	z, err := os.Open(h.zoneFile)
	if err != nil {
		log.Fatalf("cannot read file: %s", err)
	}
	defer z.Close()
	log.Printf("[zone] reading file '%s'", h.zoneFile)

	zp := dns.NewZoneParser(z, h.origin, "")
	for {
		rr, ok := zp.Next()
		if !ok {
			break
		}
		h.records = append(h.records, rr)
	}
}

func (h *Handler) watchConfig() {
	for {
		stat, err := os.Stat(h.zoneFile)
		if err != nil {
			log.Fatal("failed checking key file modification time: %w", err)
		}

		if stat.ModTime().After(h.cachedZoneFileModTime) {
			h.loadZonefile()
			h.cachedZoneFileModTime = stat.ModTime()
		}
		time.Sleep(confPollInterval)
	}
}

func (h *Handler) handleRecord(m *dns.Msg, record dns.RR, q dns.Question) string {
	logMsg := ""
	rname := strings.ToLower(record.Header().Name)
	qname := strings.ToLower(q.Name)
	if rname == "" {
		rname = h.origin
		record.Header().Name = h.origin
	}
	if rname != qname {
		return logMsg
	}

	if record.Header().Rrtype != q.Qtype {
		switch record.Header().Rrtype {
		case dns.TypeCNAME:
			cname := record.(*dns.CNAME)
			nm := m.Copy()
			nm.SetQuestion(cname.Target, dns.TypeA)
			rmsg, rlog := h.handleQuery(nm)
			log.Println(rlog)
			if rmsg != nil {
				m.Answer = append(m.Answer, rmsg.Answer...)
			} else {
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

func (h *Handler) handleQuery(m *dns.Msg) (*dns.Msg, string) {
	h.wg.Wait()

	logMsg := ""
	for _, q := range m.Question {
		logMsg = fmt.Sprintf("%s[zone] query=%s", logMsg, q.String())
		for _, record := range h.records {
			rlog := h.handleRecord(m, record, q)
			logMsg = fmt.Sprintf("%s%s", logMsg, rlog)
		}
	}
	if len(m.Answer) == 0 {
		logMsg = fmt.Sprintf("%s answer=no-answer", logMsg)
		return nil, logMsg
	}
	return m, logMsg
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	logMsg := ""

	switch r.Opcode {
	case dns.OpcodeQuery:
		m, logMsg = h.handleQuery(m)
	}

	log.Println(logMsg)
	if m != nil {
		m.Rcode = dns.RcodeSuccess
		w.WriteMsg(m)
		return
	}

	h.Next.ServeDNS(w, r)
}
