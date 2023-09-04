package recursor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"time"

	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
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
	resolverMaxLevel = 8
)

type Recursor struct {
	cache   *recursorCache
	nsCache *recursorCache

	mu      sync.Mutex
	lockmap map[string]*sync.Mutex
}

func New(datadir string) *Recursor {
	r := &Recursor{
		lockmap: make(map[string]*sync.Mutex),
	}
	if datadir != "" {
		log.Printf("[recursor] enabling file based cache")
		r.cache = newRecursorCache(filepath.Join(datadir, "cache", "addr"), "cache")
		r.nsCache = newRecursorCache(filepath.Join(datadir, "cache", "ns"), "nscache")
	}
	return r
}

func (r *Recursor) Query(ctx context.Context, req *dns.Msg, isIPV6 bool) (*dns.Msg, error) {
	cc := &ResolverContext{
		RecursionCount: 0,
	}
	ctx = context.WithValue(ctx, ResolverContextKey, cc)

	// if r.cache != nil {
	// 	ans, cacheErr := r.cache.Get(req.Question[0], "#")
	// 	if cacheErr == nil {
	// 		return ans, nil
	// 	}
	// }

	ans, err := r.resolve(ctx, req, isIPV6)
	if err != nil {
		return nil, err
	}

	utils.MsgSetupEdns(ans)
	ans.Authoritative = false

	// if r.cache != nil {
	// 	r.cache.Set(req.Question[0], "#", ans)
	// }

	return ans, nil
}

func (r *Recursor) buildServers(ctx context.Context, ans *dns.Msg, zone string) (*authServers, error) {
	servers := &authServers{
		Zone: zone,
	}
	if len(ans.Ns) == 0 {
		return nil, errors.New("no NS record found")
	}
	// log.Printf("buildServers. zone=%s\n\n%s", zone, ans)

	searchIp := func(e dns.RR) bool {
		ret := false
		switch e.Header().Rrtype {
		case dns.TypeA:
			ret = true
			a := e.(*dns.A)
			servers.List = append(servers.List, NSServer{
				Addr:    a.A.String(),
				Version: IPv4,
			})
		case dns.TypeAAAA:
			ret = true
			aaaa := e.(*dns.AAAA)
			servers.List = append(servers.List, NSServer{
				Addr:    aaaa.AAAA.String(),
				Version: IPv6,
			})
		}
		return ret
	}

	ipFound := false
	// search in answer section
	for _, e := range ans.Answer {
		ipFound = searchIp(e)
	}
	if ipFound {
		return servers, nil
	}

	toResolve := []string{}
	ipFound = false
	for _, rr := range ans.Ns {
		if _, ok := rr.(*dns.NS); !ok {
			continue
		}
		ns := rr.(*dns.NS)
		// log.Printf("||| ns: %s, searching for ip", ns.Ns)

		// search ip in extra section
		for _, e := range ans.Extra {
			if e.Header().Name != ns.Ns {
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

	// we still don't have any ip. try to resolve from the toResolve list
	if !ipFound {
		for _, ns := range toResolve {
			ra := new(dns.Msg)
			ra.SetQuestion(ns, dns.TypeA)
			rans, err := r.resolve(ctx, ra, false)
			if err != nil {
				continue
			}
			for _, e := range rans.Answer {
				searchIp(e)
			}
		}
	}

	// if we are here we don't have any place to search anymore
	if len(servers.List) == 0 {
		return nil, errors.New("can't find auth nameservers")
	}

	return servers, nil
}

func (r *Recursor) resolveNS(ctx context.Context, req *dns.Msg, isIPV6 bool, offset int) (*authServers, error) {
	q := req.Question[0]

	end := false
	var i int

	i, end = dns.NextLabel(q.Name, offset)
	if end {
		return getRootServers(), nil
	}
	zone := dns.Fqdn(q.Name[i:])

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(zone, dns.TypeNS)

	log.Printf("### zone: %s, qname: %s", zone, q.Name)
	rservers, err := r.resolveNS(ctx, req, isIPV6, offset+i)
	if err != nil {
		return nil, err
	}

	s, err := rservers.peekOne(isIPV6)
	if err != nil {
		return nil, err
	}
	resp, err := r.queryNS(nsReq, s.withPort(), false)
	if err != nil {
		return nil, err
	}
	servers, err := r.buildServers(ctx, resp, zone)
	if err != nil {
		// no nameservers found
		// go to upper zone and try again
		i, end := dns.NextLabel(zone, 0)
		if end {
			return servers, err
		}
		next := dns.Fqdn(zone[i:])
		nsReq := new(dns.Msg)
		nsReq.SetQuestion(next, dns.TypeNS)
		servers, err = r.resolveNS(ctx, nsReq, isIPV6, 0)
	}

	return servers, err
}

func (r *Recursor) resolve(ctx context.Context, req *dns.Msg, isIPV6 bool) (*dns.Msg, error) {
	rc := ctx.Value(ResolverContextKey).(*ResolverContext)
	rc.RecursionCount++
	if rc.RecursionCount >= resolverMaxLevel {
		return nil, errors.New("resolve: recursionMaxLevel reached")
	}
	ctx = context.WithValue(ctx, ResolverContextKey, rc)

	q := req.Question[0]

	servers, err := r.resolveNS(ctx, req, isIPV6, 0)
	if err != nil {
		return nil, err
	}
	// log.Printf("%s", servers)

	s, err := servers.peekOne(isIPV6)
	if err != nil {
		return nil, err
	}

	ans, err := r.queryNS(req, s.withPort(), false)
	if err != nil {
		return nil, err
	}

	if len(ans.Answer) == 0 && len(ans.Ns) > 0 {
		servers, err := r.buildServers(ctx, ans, q.Name)
		if err != nil {
			return nil, err
		}

		s, err := servers.peekOne(isIPV6)
		if err != nil {
			return nil, err
		}
		ans, err = r.queryNS(req, s.withPort(), false)
		if err != nil {
			return nil, err
		}
	}

	haveAnswer := false
	for _, rr := range ans.Answer {
		if rr.Header().Name == q.Name && rr.Header().Rrtype == q.Qtype {
			haveAnswer = true
		}
	}
	// deal with CNAMES
	if !haveAnswer {
		resp := ans.Copy()
		maxLoop := cnameChainMaxDeep
		for {
			rr := utils.MsgGetAnswerByType(resp, dns.TypeCNAME)
			if rr != nil && rr.Header().Name == q.Name {
				cname := rr.(*dns.CNAME)
				newReq := new(dns.Msg)
				newReq.SetQuestion(cname.Target, q.Qtype)
				resp, err := r.resolve(ctx, newReq, isIPV6)
				if err == nil {
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

	// haveAnswer := false
	// for _, rr := range ans.Answer {
	// 	if rr.Header().Name == q.Name && rr.Header().Rrtype == q.Qtype {
	// 		haveAnswer = true
	// 	}
	// }

	// // deal with cnames
	// if !haveAnswer {
	// 	resp := ans.Copy()
	// 	maxLoop := cnameChainMaxDeep
	// 	for {

	// 		rr := utils.MsgGetAnswerByType(resp, dns.TypeCNAME)
	// 		if rr != nil && rr.Header().Name == q.Name {
	// 			cname := rr.(*dns.CNAME)
	// 			newReq := new(dns.Msg)
	// 			newReq.SetQuestion(cname.Target, q.Qtype)

	// 			nsaddr := r.getRootNS(isIPV6)
	// 			resp, err = r.resolve(ctx, newReq, isIPV6, 0, nsaddr)

	// 			if err == nil {
	// 				ans.Answer = append([]dns.RR{rr}, resp.Answer...)
	// 				for _, rr := range ans.Answer {
	// 					if rr.Header().Rrtype == q.Qtype {
	// 						haveAnswer = true
	// 					}
	// 				}
	// 			}
	// 		}
	// 		if haveAnswer {
	// 			break
	// 		}
	// 		maxLoop--
	// 		if maxLoop == 0 {
	// 			break
	// 		}
	// 	}
	// }

	// if !haveAnswer {
	// 	if depth+1 > len(labels) {
	// 		for _, rr := range ans.Ns {
	// 			if _, ok := rr.(*dns.SOA); ok {
	// 				soa := new(dns.Msg)
	// 				soa.Answer = append(soa.Answer, rr)
	// 				soa.SetRcode(ans, ans.Rcode)
	// 				return soa, nil
	// 			}
	// 		}
	// 	} else {
	// 		return r.resolve(ctx, req, isIPV6, depth+1, nsaddr)
	// 	}
	// }

	// return ans, nil
}

func (r *Recursor) queryNS(req *dns.Msg, nsaddr string, useCache bool) (*dns.Msg, error) {
	haveCache := (r.cache != nil) && useCache

	q := req.Question[0]

	// countLabels := dns.CountLabel(q.Name)
	cacheKey := fmt.Sprintf("%s_%d_%d", q.Name, q.Qtype, q.Qclass)
	if haveCache {

		// Always get from cache root NS answers
		// if countLabels <= 1 {
		// 	ans, err := r.cache.GetByKey(cacheKey)
		// 	if err == nil {
		// 		return ans, nil
		// 	}
		// }

		ans, err := r.cache.Get(q, nsaddr)
		if err == nil {
			return ans, nil
		}

		// if countLabels > 1 {
		// 	cacheKey = r.cache.BuildKey(q, nsaddr)
		// }

		var emu *sync.Mutex
		// get or create a new mutex for the cache key in a thread
		// safe way
		r.mu.Lock()
		if tmp, ok := r.lockmap[cacheKey]; ok {
			emu = tmp
		} else {
			emu = new(sync.Mutex)
			r.lockmap[cacheKey] = emu
		}
		r.mu.Unlock()

		// no more then one concurrent request to the upstream for the given cache key, so
		// I'm taking the lock here
		emu.Lock()
		// cleanup the lockmap at the end and unlock
		defer func() {
			r.mu.Lock()
			defer r.mu.Unlock()

			delete(r.lockmap, cacheKey)
			emu.Unlock()
		}()

		// Another coroutine (the non locked one) likely has filled the cache already
		// so take the advantage here
		// if countLabels <= 1 {
		// 	ans, err := r.cache.GetByKey(cacheKey)
		// 	if err == nil {
		// 		return ans, nil
		// 	}
		// }
		ans, err = r.cache.Get(q, nsaddr)
		if err == nil {
			return ans, nil
		}
	}

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
		ans, _, err := client.Exchange(req, nsaddr)
		if err != nil {
			return nil, err
		}

		if !ans.Truncated {
			if haveCache {
				// if countLabels == 1 {
				// 	// Always cache root NS answers
				// 	r.cache.SetWithKey(cacheKey, ans)
				// } else {
				// 	r.cache.Set(q, nsaddr, ans)
				// }
				r.cache.Set(q, nsaddr, ans)
			}

			return ans, nil
		}
		if network == "tcp" {
			return nil, errors.New("cannot get a non truncated answer")
		}
		network = "tcp"
	}
}
