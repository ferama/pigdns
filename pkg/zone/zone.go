package zone

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/miekg/dns"
)

type Handler struct {
	Next dns.Handler

	zoneFile string
	domain   string

	records []dns.RR

	wg sync.WaitGroup
}

func New(next dns.Handler, domain string, zoneFile string) dns.Handler {
	h := &Handler{
		Next:     next,
		records:  make([]dns.RR, 0),
		zoneFile: zoneFile,
		domain:   domain,
	}

	if zoneFile != "" {
		h.loadZonefile()
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

	origin := fmt.Sprintf("%s.", h.domain)
	zp := dns.NewZoneParser(z, origin, "")
	for {
		rr, ok := zp.Next()
		if !ok {
			break
		}
		h.records = append(h.records, rr)
	}
}

func (h *Handler) watchConfig() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()
	err = watcher.Add(h.zoneFile)
	if err != nil {
		log.Fatal(err)
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) {
				log.Println("[zone] modified file:", event.Name)
				h.loadZonefile()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("error:", err)
		}
	}
}

func (h *Handler) parseQuery(m *dns.Msg) (*dns.Msg, string) {
	h.wg.Wait()

	logMsg := ""
	haveAnswer := false
	for _, q := range m.Question {
		logMsg = fmt.Sprintf("%s[zone] query=%s", logMsg, q.String())
		for _, record := range h.records {
			rname := strings.ToLower(record.Header().Name)
			qname := strings.ToLower(q.Name)
			if rname != qname {
				continue
			}

			if record.Header().Rrtype != q.Qtype {
				continue
			}

			m.Answer = append(m.Answer, record)
			haveAnswer = true

			logMsg = fmt.Sprintf("%s answer=%s", logMsg, record)
		}
	}
	if !haveAnswer {
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
		w.WriteMsg(m)
		return
	}

	h.Next.ServeDNS(w, r)
}
