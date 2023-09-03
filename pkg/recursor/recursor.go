package recursor

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
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
	resolverMaxLevel = 512
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

	if r.cache != nil {
		ans, cacheErr := r.cache.Get(req.Question[0], "#")
		if cacheErr == nil {
			return ans, nil
		}
	}

	ans, err := r.resolve(ctx, req, isIPV6, 0)
	if err != nil {
		return nil, err
	}

	utils.MsgSetupEdns(ans)
	ans.Authoritative = false

	if r.cache != nil {
		r.cache.Set(req.Question[0], "#", ans)
	}

	return ans, nil
}

// given an answer msg, tries to get dns ip address.
// if the ans is authoritative it searches into Answer message section
// if not it tries to get it from Extra section
func (r *Recursor) resolveNSIPFromAns(ans *dns.Msg, isIPV6 bool) (string, error) {

	ipv4 := []net.IP{}
	ipv6 := []net.IP{}

	for _, e := range ans.Answer {
		switch e.Header().Rrtype {
		case dns.TypeA:
			a := e.(*dns.A)
			ipv4 = append(ipv4, a.A)
		case dns.TypeAAAA:
			aaaa := e.(*dns.AAAA)
			ipv6 = append(ipv6, aaaa.AAAA)
		}
	}

	if len(ipv4) == 0 && len(ipv6) == 0 {
		if len(ans.Ns) == 0 {
			return "", errors.New("no NS record found")
		}
		n := rand.Intn(len(ans.Ns))
		rr := ans.Ns[n]
		if _, ok := rr.(*dns.NS); !ok {
			return "", errors.New("not a NS record")
		}
		ns := rr.(*dns.NS)

		for _, e := range ans.Extra {
			if e.Header().Name != ns.Ns {
				continue
			}
			switch e.Header().Rrtype {
			case dns.TypeA:
				a := e.(*dns.A)
				ipv4 = append(ipv4, a.A)
			case dns.TypeAAAA:
				aaaa := e.(*dns.AAAA)
				ipv6 = append(ipv6, aaaa.AAAA)
			}
		}
	}

	var ipv4res net.IP
	var ipv6res net.IP
	if len(ipv4) > 0 {
		ipv4res = ipv4[rand.Intn(len(ipv4))]
	}
	if len(ipv6) > 0 {
		ipv6res = ipv6[rand.Intn(len(ipv6))]
	}
	if ipv6res != nil && isIPV6 {
		return fmt.Sprintf("[%s]:53", ipv6res), nil
	}
	if ipv4res != nil && !isIPV6 {
		return fmt.Sprintf("%s:53", ipv4res), nil
	}
	return "", errors.New("no ns record found")
}

func (r *Recursor) buildServers(ans *dns.Msg, zone string) (*authServers, error) {
	servers := &authServers{
		Zone: zone,
	}
	if len(ans.Ns) == 0 {
		return nil, errors.New("no NS record found")
	}
	// log.Printf("buildServers. zone=%s\n\n%s", zone, ans)

	for _, rr := range ans.Ns {
		if _, ok := rr.(*dns.NS); !ok {
			continue
		}
		ns := rr.(*dns.NS)

		// find ip in extra
		ipFound := false
		for _, e := range ans.Extra {
			if e.Header().Name != ns.Ns {
				continue
			}
			switch e.Header().Rrtype {
			case dns.TypeA:
				ipFound = true
				a := e.(*dns.A)
				servers.List = append(servers.List, NSServer{
					Addr:    a.A.String(),
					Version: IPv4,
				})
			case dns.TypeAAAA:
				ipFound = true
				aaaa := e.(*dns.AAAA)
				servers.List = append(servers.List, NSServer{
					Addr:    aaaa.AAAA.String(),
					Version: IPv6,
				})
			}
		}

		if !ipFound {
			// TODO
			log.Printf("TODO: ns fqdn to resolve '%s'", ns.Ns)
		}
	}

	return servers, nil
}

func (r *Recursor) resolveNS(ctx context.Context, req *dns.Msg, isIPV6 bool, offset int) (*authServers, error) {
	q := req.Question[0]

	end := false
	var i int

	// for {
	i, end = dns.NextLabel(q.Name, offset)
	if end {
		return getRootServers(), nil
	}
	zone := dns.Fqdn(q.Name[i:])

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(zone, dns.TypeNS)
	log.Printf("### zone: %s", zone)
	// log.Printf(nsReq.String())
	// res, err := r.nsCache.Get(nsReq.Question[0], "")
	// if err == nil {
	// 	res, _ := r.resolveNSIPFromAns(res, isIPV6)
	// 	return res, nil
	// }

	rservers, err := r.resolveNS(ctx, req, isIPV6, offset+i)
	if err != nil {
		return nil, err
	}

	s := rservers.peekOne()
	resp, err := r.queryNS(nsReq, s.withPort(), false)
	if err != nil {
		return nil, err
	}

	// log.Printf("%s", resp)
	servers, err := r.buildServers(resp, zone)
	log.Printf("%s", servers)
	return servers, err

	// // r.nsCache.Set(nsReq.Question[0], "", resp)
	// nsaddr, err = r.resolveNSIPFromAns(resp, isIPV6)

	// if err != nil {
	// 	if len(resp.Ns) > 0 {
	// 		for _, rr := range resp.Ns {
	// 			if _, ok := rr.(*dns.NS); ok {
	// 				log.Printf("====== ")
	// 				nsReq := new(dns.Msg)
	// 				nsReq.SetQuestion(rr.Header().Name, dns.TypeNS)
	// 				nsaddr, err := r.resolveNS(ctx, nsReq, isIPV6, 0)
	// 				log.Printf("I-nsaddr: %s, err: %s", nsaddr, err)
	// 				// if err != nil {
	// 				// 	return r.resolveNS(ctx, req, isIPV6, offset)
	// 				// }
	// 			}
	// 		}
	// 	}
	// }

}

func (r *Recursor) resolve(ctx context.Context, req *dns.Msg, isIPV6 bool, depth int) (*dns.Msg, error) {
	rc := ctx.Value(ResolverContextKey).(*ResolverContext)
	rc.RecursionCount++
	if rc.RecursionCount >= resolverMaxLevel {
		return nil, errors.New("resolve: recursionMaxLevel reached")
	}
	ctx = context.WithValue(ctx, ResolverContextKey, rc)

	// q := req.Question[0]

	_, err := r.resolveNS(ctx, req, isIPV6, 0)
	if err != nil {
		return nil, err
	}

	// log.Printf("nsaddr: %s", nsaddr)
	// i, start := dns.PrevLabel(q.Name, depth)
	// log.Printf("i: %d, start: %v, n: %s", i, start, dns.Fqdn(q.Name[i:]))
	// labels := dns.SplitDomainName(q.Name)

	ans := new(dns.Msg)
	return ans, nil

	// slices.Reverse(labels)

	// if depth > len(labels) {
	// 	return nil, errors.New("no answer: max depth reached")
	// }

	// l := labels[0:depth]

	// slices.Reverse(l)
	// fqdn := dns.Fqdn(strings.Join(l, "."))

	// r1 := new(dns.Msg)
	// r1.SetQuestion(fqdn, q.Qtype)
	// log.Printf("$$$ q: %s, labels: %s, l: %s, cl: %d", q.Name, labels, l, dns.CountLabel(r1.Question[0].Name))

	// // this prevents a recursion loop
	// // In practice this only happens if we receive a query for
	// // . or tld for the first time
	// useCache := true
	// if dns.CountLabel(q.Name) <= 1 {
	// 	log.Printf("ignoring cache. q: %s", q.Name)
	// 	useCache = false
	// }
	// ans, err := r.queryNS(r1, nsaddr, useCache)
	// if err != nil {
	// 	return nil, err
	// }

	// if len(ans.Answer) == 0 && len(ans.Ns) > 0 {
	// 	// find the delegate nameserver address
	// 	nextNsaddr, err := r.resolveNS(ctx, ans, isIPV6)
	// 	if err != nil {
	// 		if depth+1 > len(labels) {
	// 			for _, rr := range ans.Ns {
	// 				if _, ok := rr.(*dns.SOA); ok {
	// 					soa := new(dns.Msg)
	// 					soa.Ns = append(soa.Ns, rr)
	// 					soa.SetRcode(ans, ans.Rcode)
	// 					return soa, nil
	// 				}
	// 			}
	// 		}
	// 		// if we can't resolve resolve NS because we have soa
	// 		// records only or errors in NS field etc, try to
	// 		// get an answer increasing depth level
	// 		return r.resolve(ctx, req, isIPV6, depth+1, nsaddr)
	// 		// return nil, err
	// 	}
	// 	// go deeper
	// 	res, err := r.resolve(ctx, req, isIPV6, depth+1, nextNsaddr)
	// 	if err != nil {
	// 		// resolve using the new addr
	// 		res, err = r.resolve(ctx, req, isIPV6, depth, nextNsaddr)
	// 		if err != nil {
	// 			return nil, err
	// 		}
	// 	}
	// 	return res, err
	// }

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

// func (r *Recursor) getRootNS(isIPV6 bool) string {
// 	var nsaddr string
// 	if isIPV6 {
// 		nsaddr = fmt.Sprintf("[%s]:53", getRootNSIPv6())
// 	} else {
// 		nsaddr = fmt.Sprintf("%s:53", getRootNSIPv4())
// 	}

// 	return nsaddr
// }

func (r *Recursor) queryNS(req *dns.Msg, nsaddr string, useCache bool) (*dns.Msg, error) {
	haveCache := (r.cache != nil) && useCache

	q := req.Question[0]

	countLabels := dns.CountLabel(q.Name)
	cacheKey := fmt.Sprintf("%s_%d_%d", q.Name, q.Qtype, q.Qclass)
	if haveCache {

		// Always get from cache root NS answers
		if countLabels <= 1 {
			ans, err := r.cache.GetByKey(cacheKey)
			if err == nil {
				return ans, nil
			}
		}

		ans, err := r.cache.Get(q, nsaddr)
		if err == nil {
			return ans, nil
		}

		if countLabels > 1 {
			cacheKey = r.cache.BuildKey(q, nsaddr)
		}

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
		if countLabels <= 1 {
			ans, err := r.cache.GetByKey(cacheKey)
			if err == nil {
				return ans, nil
			}
		}
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
			log.Printf("[recursor] quering ROOT ns=%s, q=%s", tmp, qname)
		} else {
			log.Printf("[recursor] quering ns=%s, q=%s", nsaddr, qname)
		}
		ans, _, err := client.Exchange(req, nsaddr)
		if err != nil {
			return nil, err
		}

		if !ans.Truncated {
			if haveCache {
				if countLabels == 1 {
					// Always cache root NS answers
					r.cache.SetWithKey(cacheKey, ans)
				} else {
					r.cache.Set(q, nsaddr, ans)
				}
			}

			return ans, nil
		}
		if network == "tcp" {
			return nil, errors.New("cannot get a non truncated answer")
		}
		network = "tcp"
	}
}
