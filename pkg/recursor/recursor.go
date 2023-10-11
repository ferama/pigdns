package recursor

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ferama/pigdns/pkg/oneinflight"
	"github.com/ferama/pigdns/pkg/pigdns"
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

const recursorContextKey contextKey = "recursor-context"

type recursorContext struct {
	RecursionCount int
	ToResolveList  []string
}

const (
	// timeout until error
	dialTimeout = 2 * time.Second

	// how deeply we will search for cnames
	cnameChainMaxDeep = 16

	// resolver will be called recursively. the recustion
	// count cannot be greater than resolverMaxLevel
	resolverMaxLevel = 24
)

type Recursor struct {
	ansCache *recursorCache
	nsCache  *nsCache

	rootkeys []dns.RR

	oneInFlight *oneinflight.OneInFlight
}

func New(datadir string) *Recursor {
	r := &Recursor{
		oneInFlight: oneinflight.New(),
		ansCache:    newRecursorCache(filepath.Join(datadir, "cache", "addr"), "ipcache"),
		nsCache:     newNSCache(filepath.Join(datadir, "cache", "ns"), "nscache"),
	}

	r.rootkeys = []dns.RR{}
	for _, k := range rootKeys {
		rr, err := dns.NewRR(k)
		if err != nil {
			log.Fatal().Msgf("invalid root key: %s", err.Error())
		}
		r.rootkeys = append(r.rootkeys, rr)
	}

	log.Printf("[recursor] enabling file based cache")

	return r
}

// func (r *Recursor) getDNSKEY(zone string, servers *authServers) []dns.RR {
func (r *Recursor) getDNSKEY(zone string) []dns.RR {
	req := new(dns.Msg)
	req.SetQuestion(zone, dns.TypeDNSKEY)
	// utils.MsgSetupEdns(req)

	keys := []dns.RR{}

	// qr := newQueryRacer(servers, req, false)
	// resp, err := qr.run()
	// if err != nil {
	// 	return keys
	// }

	resp, err := r.Query(context.TODO(), req, false)
	if err != nil {
		log.Error().Msg(err.Error())
		return keys
	}

	for _, rr := range resp.Answer {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, dnskey)
		}
	}

	return keys
}

func (r *Recursor) Query(ctx context.Context, req *dns.Msg, isIPV6 bool) (*dns.Msg, error) {
	cc := &recursorContext{
		RecursionCount: 0,
		ToResolveList:  make([]string, 0),
	}
	ctx = context.WithValue(ctx, recursorContextKey, cc)

	q := req.Question[0]
	cacheKey := fmt.Sprintf("%s_%d_%d", q.Name, q.Qtype, q.Qclass)

	// try to get the answer from cache if we have it
	cached, cacheErr := r.ansCache.Get(cacheKey)
	if cacheErr == nil {
		cached = r.cleanMsg(cached, req)
		return cached, nil
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
		ans, cacheErr := r.ansCache.Get(cacheKey)
		if cacheErr == nil {
			return &retvalue{
				Ans: ans,
				Err: nil,
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

	// log.Printf("%s", ans)

	r.ansCache.Set(cacheKey, ans)

	ans = r.cleanMsg(ans, req)
	return ans, nil
}

func (r *Recursor) cleanMsg(ans *dns.Msg, req *dns.Msg) *dns.Msg {
	// return ans
	q := req.Question[0]

	cleaned := new(dns.Msg)

	cleaned.Authoritative = false
	cleaned.SetRcode(ans, ans.Rcode)

	opt := req.IsEdns0()

	for _, rr := range ans.Answer {
		if opt != nil && opt.Do() {
			if rr.Header().Rrtype == dns.TypeRRSIG {
				cleaned.Answer = append(cleaned.Answer, rr)
				continue
			}
		}
		// exclude not requested answers (except if they contains CNAMEs)
		if rr.Header().Rrtype != dns.TypeCNAME && rr.Header().Rrtype != q.Qtype {
			continue
		}
		// exclude TypeNone from the final answer
		if rr.Header().Rrtype == dns.TypeNone {
			continue
		}

		cleaned.Answer = append(cleaned.Answer, rr)
	}
	for _, rr := range ans.Ns {
		if rr.Header().Rrtype == q.Qtype && rr.Header().Class == q.Qclass {
			cleaned.Ns = append(cleaned.Ns, rr)
		}
		if rr.Header().Rrtype == dns.TypeSOA {
			cleaned.Ns = append(cleaned.Ns, rr)
		}
	}
	return cleaned
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
			servers.List = append(servers.List, &nsServer{
				Addr:    a.A.String(),
				Version: pigdns.FamilyIPv4,
				TTL:     a.Hdr.Ttl,
			})
		case dns.TypeAAAA:
			ret = true
			aaaa := e.(*dns.AAAA)
			servers.List = append(servers.List, &nsServer{
				Addr:    aaaa.AAAA.String(),
				Version: pigdns.FamilyIPv6,
				TTL:     aaaa.Hdr.Ttl,
			})
		}
		return ret
	}

	ipFound := false
	toResolve := []string{}

	// search in answer section
	for _, rr := range ans.Answer {
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

	for _, rr := range ans.Ns {
		ipFound = false
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

	rc := ctx.Value(recursorContextKey).(*recursorContext)

	// if we have NS not resolved in Extra section, resolve them
	for _, ns := range toResolve {

		// prevents loops. if this ns was already in context in a previous
		// recursion, do not put it again in loop.
		if slices.Contains(rc.ToResolveList, ns) {
			break
		}
		rc.ToResolveList = append(rc.ToResolveList, ns)

		ra := new(dns.Msg)
		if isIPV6 {
			ra.SetQuestion(ns, dns.TypeAAAA)
		} else {
			ra.SetQuestion(ns, dns.TypeA)
		}
		rans, err := r.resolve(ctx, ra, isIPV6)

		if err != nil {
			if err == errRecursionMaxLevel {
				break
			}
			continue
		}

		for _, e := range rans.Answer {
			searchIp(e)
		}
	}

	// if we are here we don't have any place to search anymore
	if len(servers.List) == 0 {
		return nil, errNoNSfound
	}
	return servers, nil
}

// resolveNS builds an authServers object filling it with zone and resolved related nameservers ips
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

	cached, err := r.nsCache.Get(zone)
	if err == nil {
		return nil, cached, nil
	}

	// run recursively here. the recursion will end when we will
	// encounter the root zone
	resp, rservers, err := r.resolveNS(ctx, req, isIPV6, i)
	if err != nil {
		return resp, nil, err
	}

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(zone, dns.TypeNS)

	qr := newQueryRacer(rservers, nsReq, isIPV6)
	resp, err = qr.run()
	if err != nil {
		return resp, nil, err
	}

	servers, err := r.buildServers(ctx, resp, zone, isIPV6)
	if err != nil {
		if err == errRecursionMaxLevel {
			return resp, servers, err
		}
		// no nameservers found
		// return the latest servers found (rserver), and hope
		// for an answer there
		servers = rservers
		// reset error
		err = nil
	}

	if err == nil {
		r.nsCache.Set(servers)
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
	rc := ctx.Value(recursorContextKey).(*recursorContext)
	rc.RecursionCount++
	if rc.RecursionCount >= resolverMaxLevel {
		log.Printf("///////// RecursionLimit %d", rc.RecursionCount)
		return nil, errRecursionMaxLevel
	}
	ctx = context.WithValue(ctx, recursorContextKey, rc)

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

	qr := newQueryRacer(servers, req, isIPV6)
	ans, err := qr.run()
	if err != nil {
		return nil, err
	}

	loop := 0
	// TODO: investigate the 3 here
	// if I don't introduce it this will not work as expected (it should return a soa response)
	// Ex: dig @127.0.0.1 dprodmgd104.aa-rt.sharepoint.com
	for loop < 3 {
		if len(ans.Answer) == 0 && len(ans.Ns) > 0 {
			// no asnwer from the previous query but we got nameservers instead
			// Get nameservers ips and try to query them
			servers, err := r.buildServers(ctx, ans, q.Name, isIPV6)
			if err != nil {
				// soa answer
				return ans, nil
			}
			// log.Printf("%s", servers)

			qr := newQueryRacer(servers, req, isIPV6)
			ans, err = qr.run()
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
		maxLoop := cnameChainMaxDeep
		for {
			ansCopy := ans.Copy()
			var rr dns.RR
			rset := utils.MsgGetAnswerByType(ansCopy, dns.TypeCNAME, "")
			if len(rset) > 0 {
				rr = rset[0]
			}
			if rr != nil && strings.EqualFold(rr.Header().Name, q.Name) {
				cname := rr.(*dns.CNAME)
				// risgs := utils.MsgGetAnswerByType(ansCopy, dns.TypeRRSIG, cname.Header().Name)

				rc := ctx.Value(recursorContextKey).(*recursorContext)
				// prevents loops. if this ns was already in context in a previous
				// recursion, do not put it again in loop.
				if slices.Contains(rc.ToResolveList, cname.Target) {
					break
				}
				rc.ToResolveList = append(rc.ToResolveList, cname.Target)

				newReq := new(dns.Msg)
				newReq.SetQuestion(cname.Target, q.Qtype)
				// utils.MsgSetupEdns(newReq)

				// run a new query here to solve the CNAME
				resp, err := r.Query(ctx, newReq, isIPV6)
				if err == errRecursionMaxLevel {
					return nil, err
				}

				if err == nil {
					soa := r.findSoa(resp)
					if soa != nil {
						return soa, nil
					}

					for _, rr := range ans.Answer {
						if rr.Header().Rrtype == q.Qtype {
							haveAnswer = true
						}
					}
					if !haveAnswer {
						ans.Answer = []dns.RR{rr}
						ans.Answer = append(ans.Answer, resp.Answer...)
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

	rrsigs := utils.MsgGetAnswerByType(ans, dns.TypeRRSIG, "")
	dnssecVerified := false
	for _, rrsig := range rrsigs {
		sig := rrsig.(*dns.RRSIG)
		log.Printf("[DNSKEY] q: '%s' signer name: '%s'", q.Name, sig.SignerName)
		keys := r.getDNSKEY(sig.SignerName)
		for _, krr := range keys {
			key := krr.(*dns.DNSKEY)
			rrset := utils.MsgGetAnswerByType(ans, sig.TypeCovered, q.Name)
			if len(rrset) == 0 {
				continue
			}
			err := sig.Verify(key, rrset)
			if err == nil {
				dnssecVerified = true
			}
		}
	}
	if dnssecVerified {
		log.Printf("[DNSSEC] verfified for '%s'", q.Name)
	}

	return ans, nil
}
