package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
)

type contextKey string

const ResolverContextKey contextKey = "resolver-middleware-context"

type ResolverContext struct {
	RecursionCount int
}

const (
	// timeout until error
	dialTimeout       = 3 * time.Second
	maxRetriesOnError = 5

	// how deeply we will search for cnames
	cnameChainMaxDeep = 16

	// getAnswer will be called recursively. the recustion
	// count cannot be greater than recursionMaxLevel
	recursionMaxLevel = 64

	// for logging
	handlerName = "resolver"
)

type handler struct {
	Next pigdns.Handler

	cache *resolverCache
}

func NewResolver(next pigdns.Handler, datadir string) *handler {
	h := &handler{
		Next:  next,
		cache: newResolverCache(datadir),
	}
	return h
}

func (h *handler) resolveNS(ctx context.Context, r *pigdns.Request, resp *dns.Msg) (string, error) {
	n := rand.Intn(len(resp.Ns))
	rr := resp.Ns[n]
	if _, ok := rr.(*dns.NS); !ok {
		return "", fmt.Errorf("%s not a NS record", rr)
	}
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

		rootNS := h.getRootNS(r)

		var newReq *pigdns.Request
		if r.FamilyIsIPv6() {
			newReq = r.NewWithQuestion(ns.Ns, dns.TypeAAAA)
		} else {
			newReq = r.NewWithQuestion(ns.Ns, dns.TypeA)
		}

		var ipv4 net.IP
		var ipv6 net.IP

		retryForIPv4 := 1
		for ipv4 == nil && ipv6 == nil && retryForIPv4 >= 0 {
			ans, err := h.getAnswer(ctx, newReq, rootNS)
			if err != nil {
				return "", err
			}

			for _, e := range ans.Answer {
				switch e.Header().Rrtype {
				case dns.TypeA:
					a := e.(*dns.A)
					ipv4 = a.A
				case dns.TypeAAAA:
					aaaa := e.(*dns.AAAA)
					ipv6 = aaaa.AAAA
				}
			}
			if ipv4 == nil && ipv6 == nil && r.FamilyIsIPv6() {
				newReq = r.NewWithQuestion(ns.Ns, dns.TypeA)
			}
			retryForIPv4--
		}

		if r.FamilyIsIPv6() && ipv6 != nil {
			return fmt.Sprintf("[%s]:53", ipv6), nil
		}
		return fmt.Sprintf("%s:53", ipv4), nil
	}
	if r.FamilyIsIPv6() && ipv6 != nil {
		return fmt.Sprintf("[%s]:53", ipv6), nil
	}
	return fmt.Sprintf("%s:53", ipv4), nil
}

func (h *handler) queryNS(reqMsg *dns.Msg, nsaddr string) (*dns.Msg, error) {
	network := "udp"
	qname := reqMsg.Question[0].Name
	for {
		client := &dns.Client{
			Timeout: dialTimeout,
			Net:     network,
		}

		tmp, err := netip.ParseAddrPort(nsaddr)
		if err != nil {
			return nil, fmt.Errorf("%s. nsaddr: %s", err, nsaddr)
		}
		if slices.Contains(rootNSIPv4, tmp.Addr().String()) || slices.Contains(rootNSIPv6, tmp.Addr().String()) {
			log.Printf("[resolver] quering ROOT ns=%s, q=%s", tmp, qname)
		} else {
			log.Printf("[resolver] quering ns=%s, q=%s", nsaddr, qname)
		}
		ans, _, err := client.Exchange(reqMsg, nsaddr)
		if err != nil {
			return nil, err
		}
		if !ans.Truncated {
			return ans, nil
		}
		network = "tcp"
	}
}

func (h *handler) getAnswer(ctx context.Context, req *pigdns.Request, nsaddr string) (*dns.Msg, error) {
	rc := ctx.Value(ResolverContextKey).(*ResolverContext)
	rc.RecursionCount++
	if rc.RecursionCount >= recursionMaxLevel {
		return nil, errors.New("getAnswer: recursionMaxLevel reached")
	}
	ctx = context.WithValue(ctx, ResolverContextKey, rc)

	q, err := req.Question()
	if err != nil {
		return nil, err
	}

	// try to get the answer from cache.
	// if no cached answer is present, do the recursive query
	cc := ctx.Value(collector.CollectorContextKey).(*collector.CollectorContext)
	ans, cacheErr := h.cache.Get(q, nsaddr)
	if cacheErr == nil {
		cc.CacheHits += 1
	} else {
		ans, err = h.queryNS(req.Msg, nsaddr)
		if err != nil {
			return nil, err
		}
		cq, _ := req.Question()
		h.cache.Set(cq, nsaddr, ans)
	}

	if !ans.Authoritative && len(ans.Ns) > 0 {
		// find the authoritative ns
		authNS, err := h.resolveNS(ctx, req, ans)
		if err != nil {
			return nil, err
		}
		// call getAnswer recursively
		ans, err = h.getAnswer(ctx, req, authNS)
		if err != nil {
			return nil, err
		}
		if cacheErr != nil {
			cq, _ := req.Question()
			h.cache.Set(cq, authNS, ans)
		}

	}

	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeCNAME {

		// handle CNAME loop
		maxLoop := cnameChainMaxDeep
		for {

			haveAnswer := false
			switch q.Qtype {
			case dns.TypeA:
				haveAnswer = utils.MsgGetAnswerByType(ans, dns.TypeA) != nil
			case dns.TypeAAAA:
				haveAnswer = utils.MsgGetAnswerByType(ans, dns.TypeAAAA) != nil
			case dns.TypeCNAME:
				haveAnswer = utils.MsgGetAnswerByType(ans, dns.TypeCNAME) != nil
			}

			if haveAnswer {
				break
			}

			rr := utils.MsgGetAnswerByType(ans, dns.TypeCNAME)
			if rr != nil {
				cname := rr.(*dns.CNAME)
				newReq := req.NewWithQuestion(cname.Target, q.Qtype)
				nsaddr := h.getRootNS(req)
				ans, err = h.getAnswer(ctx, newReq, nsaddr)
				if err != nil {
					return nil, err
				}
				ans.Answer = append(ans.Answer, cname)
				if cacheErr != nil {
					cq, _ := newReq.Question()
					h.cache.Set(cq, nsaddr, ans)
				}
				break
			}
			maxLoop--
			if maxLoop == 0 {
				break
			}
		}
	}

	return ans, nil
}

func (h *handler) getRootNS(r *pigdns.Request) string {
	var nsaddr string
	if r.FamilyIsIPv6() {
		nsaddr = fmt.Sprintf("[%s]:53", getRootNSIPv6())
	} else {
		nsaddr = fmt.Sprintf("%s:53", getRootNSIPv4())
	}

	return nsaddr
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

	cc := &ResolverContext{
		RecursionCount: 0,
	}
	c = context.WithValue(c, ResolverContextKey, cc)

	m := new(dns.Msg)
	retries := maxRetriesOnError
	for {
		nsaddr := h.getRootNS(r)
		m, err = h.getAnswer(c, r, nsaddr)
		if err == nil {
			break
		}
		retries--

		if retries == 0 {
			log.Err(err).
				Str("query", r.Name()).
				Msg("error on getAnswer")

			h.Next.ServeDNS(c, r)
			return
		}
	}
	if len(m.Answer) != 0 {
		cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
		cc.AnweredBy = handlerName
		m.Rcode = dns.RcodeSuccess
		m.RecursionAvailable = true
		r.Reply(m)
		return
	}

	h.Next.ServeDNS(c, r)
}
