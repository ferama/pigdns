package resolver

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/ferama/pigdns/pkg/cache"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
)

const dialTimeout = 10 * time.Second

type handler struct {
	Next pigdns.Handler

	cache cache.Cache
}

func NewResolver(next pigdns.Handler, datadir string) *handler {
	h := &handler{
		Next:  next,
		cache: cache.NewFileCache(datadir),
	}
	return h
}

func (h *handler) resolveNS(r *pigdns.Request, resp *dns.Msg) string {
	n := rand.Intn(len(resp.Ns))
	rr := resp.Ns[n]
	ns := rr.(*dns.NS)

	// root nameservers will answer filling the NS section (as authoritative)
	// and putting the resolved A and AAAA records into extra section
	// $ dig @198.41.0.4 google.it
	// ;; AUTHORITY SECTION:
	// it.			172800	IN	NS	d.dns.it.
	// it.			172800	IN	NS	r.dns.it.
	// it.			172800	IN	NS	a.dns.it.
	// it.			172800	IN	NS	nameserver.cnr.it.
	// it.			172800	IN	NS	dns.nic.it.
	// it.			172800	IN	NS	m.dns.it.

	// ;; ADDITIONAL SECTION:
	// d.dns.it.			172800	IN	A		45.142.220.39
	// d.dns.it.			172800	IN	AAAA	2a0e:dbc0::39
	// r.dns.it.			172800	IN	A		193.206.141.46
	// r.dns.it.			172800	IN	AAAA	2001:760:ffff:ffff::ca
	// a.dns.it.			172800	IN	A		194.0.16.215
	// a.dns.it.			172800	IN	AAAA	2001:678:12:0:194:0:16:215
	// nameserver.cnr.it.	172800	IN	A		194.119.192.34
	// nameserver.cnr.it.	172800	IN	AAAA	2a00:1620:c0:220:194:119:192:34
	// dns.nic.it.			172800	IN	A		192.12.192.5
	// dns.nic.it.			172800	IN	AAAA	2a00:d40:1:1::5
	// m.dns.it.			172800	IN	A		217.29.76.4
	// m.dns.it.			172800	IN	AAAA	2001:1ac0:0:200:0:a5d1:6004:2

	// we are going to extract the resolved records from the extra section
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

	// If we query the second level NS we get something like this intead:
	// $ dig @194.0.16.215 google.it
	// ;; QUESTION SECTION:
	// ;google.it.			IN	A

	// ;; AUTHORITY SECTION:
	// google.it.		10800	IN	NS	ns2.google.com.
	// google.it.		10800	IN	NS	ns4.google.com.
	// google.it.		10800	IN	NS	ns1.google.com.
	// google.it.		10800	IN	NS	ns3.google.com.
	//
	// no A or AAAA records in Extra section
	// So we here are going to ask the rootNS server who can resolve the
	// ns2.google.com. name and will recursively resolve the final A and AAAA record
	// using the authoritative nameserver
	if ipv4 == nil && ipv6 == nil {
		n := rand.Intn(len(resp.Ns))
		ns := resp.Ns[n].(*dns.NS)

		m := new(dns.Msg)
		var rootNS string
		var newReq *pigdns.Request
		if r.FamilyIsIPv6() {
			rootNS = fmt.Sprintf("[%s]:53", getRootNSIPv6())
			newReq = r.NewWithQuestion(ns.Ns, dns.TypeAAAA)
		} else {
			rootNS = fmt.Sprintf("%s:53", getRootNSIPv4())
			newReq = r.NewWithQuestion(ns.Ns, dns.TypeA)
		}

		h.getAnswer(newReq, m, "udp", rootNS)

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
		if r.FamilyIsIPv6() {
			return fmt.Sprintf("[%s]:53", ipv6)
		}
		return fmt.Sprintf("%s:53", ipv4)
	}
	if r.FamilyIsIPv6() {
		return fmt.Sprintf("[%s]:53", ipv6)
	}
	return fmt.Sprintf("%s:53", ipv4)
}

func (h *handler) getAnswer(r *pigdns.Request, m *dns.Msg, network string, nsaddr string) error {

	q, err := r.Question()
	if err != nil {
		return err
	}
	cachedMsg, err := h.cache.Get(q)
	if err == nil {
		m.Answer = append(m.Answer, cachedMsg.Answer...)
		m.Extra = append(m.Extra, cachedMsg.Extra...)
		m.Ns = append(m.Ns, cachedMsg.Ns...)

		// logMsg := fmt.Sprintf("[resolver] query=%s cached-response", r.Name())
		// log.Println(logMsg)
		return nil
	}

	client := &dns.Client{
		Timeout: dialTimeout,
		Net:     network,
	}

	tmp, _ := netip.ParseAddrPort(nsaddr)
	if slices.Contains(rootNSIPv4, tmp.Addr().String()) || slices.Contains(rootNSIPv6, tmp.Addr().String()) {
		log.Printf("[resolver] quering ROOT ns %s query=%s", tmp, r.Name())
	} else {
		log.Printf("[resolver] quering ns %s, query=%s", nsaddr, r.Name())
	}
	resp, _, err := client.Exchange(r.Msg, nsaddr)
	if err != nil {
		return err
	}

	if resp.Truncated {
		return h.getAnswer(r, m, "tcp", nsaddr)
	}

	if !resp.Authoritative && len(resp.Ns) > 0 {
		// find the authoritative ns
		addr := h.resolveNS(r, resp)
		return h.getAnswer(r, m, network, addr)
	}

	m.Answer = append(m.Answer, resp.Answer...)
	m.Extra = append(m.Extra, resp.Extra...)
	m.Ns = append(m.Ns, resp.Ns...)
	h.cache.Set(q, m)
	return nil
}

func (h *handler) ServeDNS(c context.Context, r *pigdns.Request) {
	allowedNets := viper.GetStringSlice(utils.ResolverAllowNetworks)
	allowed, err := utils.IsClientAllowed(r.ResponseWriter.RemoteAddr(), allowedNets)
	if err != nil {
		log.Fatal().Err(err)
	}
	if !allowed {
		log.Printf("[resolver] client '%s' is not allowed", r.ResponseWriter.RemoteAddr())
		h.Next.ServeDNS(c, r)
		return
	}

	m := new(dns.Msg)
	m.Authoritative = false

	// logMsg := fmt.Sprintf("[resolver] query=%s type=%s", r.Name(), r.Type())

	var nsaddr string
	if r.FamilyIsIPv6() {
		nsaddr = fmt.Sprintf("[%s]:53", getRootNSIPv6())
	} else {
		nsaddr = fmt.Sprintf("%s:53", getRootNSIPv4())
	}

	err = h.getAnswer(r, m, "udp", nsaddr)
	if err != nil {
		// logMsg = fmt.Sprintf("%s %s", logMsg, err)
		// log.Println(logMsg)
		h.Next.ServeDNS(c, r)
		return
	}

	if len(m.Answer) != 0 {
		// log.Println(logMsg)
		m.Rcode = dns.RcodeSuccess
		r.Reply(m)
		return
	}

	// logMsg = fmt.Sprintf("%s %s", logMsg, "answer=no-answer")
	// log.Println(logMsg)

	h.Next.ServeDNS(c, r)
}
