package forward

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

const dialTimeout = 10 * time.Second

type handler struct {
	Next dns.Handler

	cache *cache
}

func NewForwarder(next dns.Handler) *handler {
	h := &handler{
		Next:  next,
		cache: newCache(),
	}
	return h
}

func (h *handler) resolveNS(resp *dns.Msg) string {
	n := rand.Intn(len(resp.Ns))
	rr := resp.Ns[n]
	ns := rr.(*dns.NS)

	var ipv4 net.IP
	var ipv6 net.IP
	for _, e := range resp.Extra {
		if e.Header().Name != ns.Ns {
			continue
		}
		switch e.Header().Rrtype {
		case dns.TypeA:
			a := e.(*dns.A)
			ipv4 = a.A
		case dns.TypeAAAA:
			aaaa := e.(*dns.AAAA)
			ipv6 = aaaa.AAAA
		}
	}

	// no A or AAAA records in Extra
	if ipv4 == nil && ipv6 == nil {
		n := rand.Intn(len(resp.Ns))
		ns := resp.Ns[n].(*dns.NS)

		rootNS := fmt.Sprintf("%s:53", getRootNS())
		m := new(dns.Msg)
		m.SetQuestion(ns.Ns, dns.TypeA)
		h.getAnswer(m, "udp", rootNS)

		var ipv4 net.IP
		var ipv6 net.IP
		for _, e := range m.Answer {
			switch e.Header().Rrtype {
			case dns.TypeA:
				a := e.(*dns.A)
				ipv4 = a.A
			case dns.TypeAAAA:
				aaaa := e.(*dns.AAAA)
				ipv6 = aaaa.AAAA
			}
		}
		log.Printf("ns: %s ipv4: %s, ipv6: %s", ns.Ns, ipv4, ipv6)
		return fmt.Sprintf("%s:53", ipv4)
	}
	log.Printf("ns: %s ipv4: %s, ipv6: %s", ns.Ns, ipv4, ipv6)

	addr := fmt.Sprintf("%s:53", ipv4)
	return addr
}

func (h *handler) getAnswer(m *dns.Msg, network string, nsaddr string) error {

	q := m.Question[0]
	cachedMsg, err := h.cache.get(q)
	if err == nil {
		m.Answer = append(m.Answer, cachedMsg.Answer...)
		m.Extra = append(m.Extra, cachedMsg.Extra...)
		m.Ns = append(m.Ns, cachedMsg.Ns...)

		logMsg := fmt.Sprintf("[forward] query=%s cached-response", q.String())
		log.Println(logMsg)
		return nil
	}

	client := &dns.Client{
		Timeout: dialTimeout,
		Net:     network,
	}

	resp, _, err := client.Exchange(m, nsaddr)
	if err != nil {
		return err
	}

	log.Printf("[forward] quering ns %s, query=%s", nsaddr, q.String())
	if resp.Truncated {
		return h.getAnswer(m, "tcp", nsaddr)
	}

	if !resp.Authoritative && len(resp.Ns) > 0 {
		addr := h.resolveNS(resp)
		return h.getAnswer(m, network, addr)
	}

	m.Answer = append(m.Answer, resp.Answer...)
	m.Extra = append(m.Extra, resp.Extra...)
	m.Ns = append(m.Ns, resp.Ns...)
	h.cache.set(q, m)
	return nil
}

func (h *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	allowedNets := viper.GetStringSlice(utils.ForwardAllowNetworks)
	allowed, err := utils.IsClientAllowed(w.RemoteAddr(), allowedNets)
	if err != nil {
		log.Fatal(err)
	}
	if !allowed {
		log.Printf("[forward] client '%s' is not allowed", w.RemoteAddr())
		h.Next.ServeDNS(w, r)
		return
	}

	m := new(dns.Msg)
	m.Authoritative = false

	logMsg := ""

	q := r.Question[0]
	logMsg = fmt.Sprintf("%s[forward] query=%s", logMsg, q.String())

	m.SetQuestion(q.Name, q.Qtype)

	// nsaddr := fmt.Sprintf("%s:53", upstream[0])
	nsaddr := fmt.Sprintf("%s:53", getRootNS())
	err = h.getAnswer(m, "udp", nsaddr)
	if err != nil {
		logMsg = fmt.Sprintf("%s %s", logMsg, err)
		log.Println(logMsg)
		h.Next.ServeDNS(w, r)
		return
	}

	m.SetReply(r)
	if len(m.Answer) != 0 {
		log.Println(logMsg)
		m.Rcode = dns.RcodeSuccess
		w.WriteMsg(m)
		return
	}

	h.Next.ServeDNS(w, r)
}
