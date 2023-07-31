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

func (h *Handler) handleRecursive(r dns.RR, m *dns.Msg, qtype uint16) (*dns.Msg, string) {
	switch qtype {
	case dns.TypeCNAME:
		rc := r.(*dns.CNAME)
		nm := m.Copy()
		nm.SetQuestion(rc.Target, dns.TypeA)
		return h.parseQuery(nm)
	}

	return nil, ""
}

func (h *Handler) parseQuery(m *dns.Msg) (*dns.Msg, string) {
	h.wg.Wait()

	logMsg := ""
	for _, q := range m.Question {
		logMsg = fmt.Sprintf("%s[zone] query=%s", logMsg, q.String())
		for _, record := range h.records {
			rname := strings.ToLower(record.Header().Name)
			qname := strings.ToLower(q.Name)
			if rname == "" {
				rname = h.origin
				record.Header().Name = h.origin
			}
			if rname != qname {
				continue
			}

			if record.Header().Rrtype != q.Qtype {
				rmsg, rlog := h.handleRecursive(record, m, record.Header().Rrtype)
				log.Println(rlog)
				if rmsg != nil {
					m.Answer = append(m.Answer, rmsg.Answer...)
				} else {
					continue
				}
			}

			m.Answer = append(m.Answer, record)
			logMsg = fmt.Sprintf("%s answer=%s", logMsg, record)
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
		m, logMsg = h.parseQuery(m)
	}

	log.Println(logMsg)
	if m != nil {
		m.Rcode = dns.RcodeSuccess
		w.WriteMsg(m)
		return
	}

	h.Next.ServeDNS(w, r)
}
