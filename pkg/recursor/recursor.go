package recursor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/ferama/pigdns/pkg/oneinflight"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
)

var (
	errNoNSfound         = errors.New("can't find auth nameservers")
	errRecursionMaxLevel = errors.New("recursion max level reached")
)

type contextKey string

const ResolverContextKey contextKey = "recursor-context"

type ResolverContext struct {
	RecursionCount int
}

const (
	// timeout until error
	dialTimeout = 2 * time.Second

	// how deeply we will search for cnames
	cnameChainMaxDeep = 16

	// resolver will be called recursively. the recustion
	// count cannot be greater than resolverMaxLevel
	resolverMaxLevel = 64
)

type Recursor struct {
	cache   *recursorCache
	nsCache *nsCache

	oneInFlight *oneinflight.OneInFlight
}

func New(datadir string) *Recursor {
	r := &Recursor{
		oneInFlight: oneinflight.New(),
	}

	if datadir != "" {
		log.Printf("[recursor] enabling file based cache")
		r.cache = newRecursorCache(filepath.Join(datadir, "cache", "addr"), "cache")
		r.nsCache = newNSCache(filepath.Join(datadir, "cache", "ns"), "nscache")
	}
	return r
}

func (r *Recursor) Query(ctx context.Context, req *dns.Msg, isIPV6 bool) (*dns.Msg, error) {
	cc := &ResolverContext{
		RecursionCount: 0,
	}
	ctx = context.WithValue(ctx, ResolverContextKey, cc)

	q := req.Question[0]
	cacheKey := fmt.Sprintf("%s_%d_%d", q.Name, q.Qtype, q.Qclass)

	// try to get the answer from cache if we have it
	if r.cache != nil {
		ans, cacheErr := r.cache.Get(cacheKey)
		if cacheErr == nil {
			return ans, nil
		}
	}

	// if we don't have an answer in cache, run the query (only once concurrently
	// against the upstream nameservers)
	type retvalue struct {
		Ans *dns.Msg
		Err error
	}
	tmp := r.oneInFlight.Run(cacheKey, func(params ...any) any {
		// Another goroutine (the non locked one) likely has filled the cache already
		// so take the advantage here
		if r.cache != nil {
			ans, cacheErr := r.cache.Get(cacheKey)
			if cacheErr == nil {
				return &retvalue{
					Ans: ans,
					Err: nil,
				}
			}
		}

		ans, err := r.resolve(ctx, req, isIPV6)
		return &retvalue{
			Ans: ans,
			Err: err,
		}
	})
	res := tmp.(*retvalue)
	ans := res.Ans

	if res.Err != nil {
		return nil, res.Err
	}

	utils.MsgSetupEdns(ans)
	ans.Authoritative = false

	if r.cache != nil {
		r.cache.Set(cacheKey, ans)
	}

	return ans, nil
}

func (r *Recursor) buildServers(ctx context.Context, ans *dns.Msg, zone string, isIPV6 bool) (*authServers, error) {

	servers := &authServers{
		Zone: zone,
	}

	if len(ans.Ns) == 0 && len(ans.Answer) == 0 {
		return nil, errNoNSfound
	}

	searchIp := func(e dns.RR) bool {
		ret := false
		switch e.Header().Rrtype {
		case dns.TypeA:
			ret = true
			a := e.(*dns.A)
			servers.List = append(servers.List, nsServer{
				Addr:    a.A.String(),
				Version: IPv4,
				TTL:     a.Hdr.Ttl,
			})
		case dns.TypeAAAA:
			ret = true
			aaaa := e.(*dns.AAAA)
			servers.List = append(servers.List, nsServer{
				Addr:    aaaa.AAAA.String(),
				Version: IPv6,
				TTL:     aaaa.Hdr.Ttl,
			})
		}
		return ret
	}

	ipFound := false
	toResolve := []string{}

	// search in answer section
	for _, rr := range ans.Answer {
		ipFound = searchIp(rr)
		if ipFound {
			continue
		}

		if _, ok := rr.(*dns.NS); !ok {
			continue
		}

		// if the answer is an NS record...
		ns := rr.(*dns.NS)
		// search ip in extra section
		for _, e := range ans.Extra {
			if !strings.EqualFold(e.Header().Name, ns.Ns) {
				continue
			}
			searchIp(e)
		}
	}

	ipFound = false
	for _, rr := range ans.Ns {
		if _, ok := rr.(*dns.NS); !ok {
			continue
		}
		ns := rr.(*dns.NS)

		// search ip in extra section
		for _, e := range ans.Extra {
			if !strings.EqualFold(e.Header().Name, ns.Ns) {
				continue
			}
			ipFound = searchIp(e)
		}

		if !ipFound {
			// is a ns record without an extra section
			// put in a toResolve list and handle it after if needed
			toResolve = append(toResolve, ns.Ns)
		}
	}

	// if we have NS not resolved in Extra section, resolve them
	for _, ns := range toResolve {
		// log.Printf("||| resolving ns: %s", ns)
		ra := new(dns.Msg)
		ra.SetQuestion(ns, dns.TypeA)
		rans, err := r.resolve(ctx, ra, isIPV6)
		if err != nil {
			// log.Printf("/// err resolving ns: %s. err: %s", ns, err)
			if err == errRecursionMaxLevel {
				return nil, err
			}
			continue
		}
		// log.Printf("/// done resolving ns: %s", ns)
		for _, e := range rans.Answer {
			// a := e.(*dns.A)
			// log.Printf("| got %s", a.A)
			searchIp(e)
		}
	}

	// if we are here we don't have any place to search anymore
	if len(servers.List) == 0 {
		return nil, errNoNSfound
	}
	return servers, nil
}

// resolveNS build an authServers object filling it with zone and resolved related nameservers ips
// it returns in order:
// *dns.Msg the latest response from a queried NS server if any
// *authServers the authServers object
// error
func (r *Recursor) resolveNS(ctx context.Context, req *dns.Msg, isIPV6 bool, offset int) (*dns.Msg, *authServers, error) {
	q := req.Question[0]

	end := false
	var i int

	i, end = dns.NextLabel(q.Name, offset)
	if end {
		return nil, getRootServers(), nil
	}
	zone := dns.Fqdn(q.Name[i:])

	if r.nsCache != nil {
		cached, err := r.nsCache.Get(zone)
		if err == nil {
			return nil, cached, nil
		}
	}

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(zone, dns.TypeNS)

	// run recursively here. the recursion will end when we will
	// encounter the root zone
	resp, rservers, err := r.resolveNS(ctx, req, isIPV6, i)
	if err != nil {
		return resp, nil, err
	}

	// qr := newQueryRacer(rservers, req, isIPV6)
	// resp, err = qr.run()
	// if err != nil {
	// 	return resp, nil, err
	// }

	s, err := rservers.peekOne(isIPV6)
	if err != nil {
		return nil, nil, err
	}

	resp, err = r.queryNS(ctx, nsReq, s.withPort())
	if err != nil {
		return resp, nil, err
	}

	servers, err := r.buildServers(ctx, resp, zone, isIPV6)

	if err != nil {
		// no nameservers found
		// go to upper zone and try again
		i, end := dns.NextLabel(zone, 0)
		if end {
			return resp, nil, err
		}
		next := dns.Fqdn(zone[i:])
		nsReq := new(dns.Msg)
		nsReq.SetQuestion(next, dns.TypeNS)
		resp, servers, err = r.resolveNS(ctx, nsReq, isIPV6, 0)
	}

	if err == nil {
		if r.nsCache != nil {
			r.nsCache.Set(servers)
		}
	}

	return resp, servers, err
}

func (r *Recursor) findSoa(resp *dns.Msg) *dns.Msg {
	for _, rr := range resp.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			soa := new(dns.Msg)
			soa.Ns = append(soa.Ns, rr)
			soa.SetRcode(resp, resp.Rcode)
			return soa
		}
	}
	return nil
}

func (r *Recursor) resolve(ctx context.Context, req *dns.Msg, isIPV6 bool) (*dns.Msg, error) {
	rc := ctx.Value(ResolverContextKey).(*ResolverContext)
	rc.RecursionCount++
	if rc.RecursionCount >= resolverMaxLevel {
		log.Printf("///////// %d", rc.RecursionCount)
		return nil, errRecursionMaxLevel
	}
	ctx = context.WithValue(ctx, ResolverContextKey, rc)

	q := req.Question[0]

	resp, servers, err := r.resolveNS(ctx, req, isIPV6, 0)
	if err != nil {
		if err == errNoNSfound && resp != nil && len(resp.Ns) > 0 {
			soa := r.findSoa(resp)
			if soa != nil {
				return soa, nil
			}
		}
		return nil, err
	}

	// qr := newQueryRacer(servers, req, isIPV6)
	// ans, err := qr.run()
	// if err != nil {
	// 	return nil, err
	// }
	s, err := servers.peekOne(isIPV6)
	if err != nil {
		return nil, err
	}

	ans, err := r.queryNS(ctx, req, s.withPort())
	if err != nil {
		return nil, err
	}

	loop := 0
	// TODO: investigate the 3 here
	// if I don't introduce it this will not work as expected (it should return a soa response)
	// dig @127.0.0.1 dprodmgd104.aa-rt.sharepoint.com
	// This should respond with a soa record too
	// dig @127.0.0.1 243.35.149.83.in-addr.arpa
	// dig @127.0.0.1 1-courier.push.apple.com aaaa
	// TODO:
	// dig @127.0.0.1 bmx.waseca.k12.mn.us.redcondor.net
	// dig @127.0.0.1 243.251.209.112.in-addr.arpa
	for loop < 3 {
		if len(ans.Answer) == 0 && len(ans.Ns) > 0 {
			// no asnwer from the previous query but we got nameservers instead
			// Get nameservers ips and try to query them
			servers, err := r.buildServers(ctx, ans, q.Name, isIPV6)
			if err != nil {
				// soa answer
				return ans, nil
			}

			// qr := newQueryRacer(servers, req, isIPV6)
			// ans, err = qr.run()
			// if err != nil {
			// 	return nil, err
			// }

			s, err := servers.peekOne(isIPV6)
			if err != nil {
				return nil, err
			}

			ans, err = r.queryNS(ctx, req, s.withPort())
			if err != nil {
				return nil, err
			}
		}
		loop++
	}

	haveAnswer := false
	for _, rr := range ans.Answer {
		if strings.EqualFold(rr.Header().Name, q.Name) && rr.Header().Rrtype == q.Qtype {
			haveAnswer = true
		}
	}
	// deal with CNAMES
	if !haveAnswer {
		ans.Ns = []dns.RR{}
		ans.Extra = []dns.RR{}
		resp := ans.Copy()
		maxLoop := cnameChainMaxDeep
		for {
			rr := utils.MsgGetAnswerByType(resp, dns.TypeCNAME)
			if rr != nil && strings.EqualFold(rr.Header().Name, q.Name) {
				cname := rr.(*dns.CNAME)
				newReq := new(dns.Msg)
				newReq.SetQuestion(cname.Target, q.Qtype)
				resp, err := r.resolve(ctx, newReq, isIPV6)
				if err == errRecursionMaxLevel {
					return nil, err
				}
				if err == nil {
					soa := r.findSoa(resp)
					if soa != nil {
						return soa, nil
					}

					ans.Answer = append([]dns.RR{rr}, resp.Answer...)
					for _, rr := range ans.Answer {
						if rr.Header().Rrtype == q.Qtype {
							haveAnswer = true
						}
					}

				}
			}
			if haveAnswer {
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

func (r *Recursor) queryNS(ctx context.Context, req *dns.Msg, nsaddr string) (*dns.Msg, error) {
	q := req.Question[0]

	// If we are here, there is no cached answer. Do query upstream
	network := "udp"
	qname := req.Question[0].Name
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
			log.Printf("[recursor] quering ROOT ns=%s q=%s t=%s", tmp, qname, dns.TypeToString[q.Qtype])
		} else {
			log.Printf("[recursor] quering ns=%s q=%s t=%s", nsaddr, qname, dns.TypeToString[q.Qtype])
		}

		ans, _, err := client.ExchangeContext(ctx, req, nsaddr)
		if err != nil {
			return nil, err
		}

		if !ans.Truncated {
			return ans, nil
		}
		if network == "tcp" {
			return nil, errors.New("cannot get a non truncated answer")
		}
		network = "tcp"
	}
}
