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
	// resolverMaxLevel = 16
)

type Recursor struct {
	ansCache *ansCache
	nsCache  *nsCache

	rootkeys []dns.RR

	oneInFlight *oneinflight.OneInFlight
}

func New(datadir string) *Recursor {
	r := &Recursor{
		oneInFlight: oneinflight.New(),
		ansCache:    newAnsCache(filepath.Join(datadir, "cache", "addr"), "ipcache"),
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

func (r *Recursor) newContext(ctx context.Context) context.Context {
	cc := &recursorContext{
		RecursionCount: 0,
		ToResolveList:  make([]string, 0),
	}
	return context.WithValue(ctx, recursorContextKey, cc)
}

func (r *Recursor) Query(ctx context.Context, req *dns.Msg, isIPV6 bool) (*dns.Msg, error) {
	ctx = r.newContext(ctx)

	q := req.Question[0]
	reqKey := fmt.Sprintf("%s_%d_%d", q.Name, q.Qtype, q.Qclass)

	// run the query (only once concurrently
	// against the upstream nameservers)
	type retvalue struct {
		Ans *dns.Msg
		Err error
	}
	tmp := r.oneInFlight.Run(reqKey, func(params ...any) any {
		ans, err := r.resolve(ctx, req, isIPV6)

		if err == nil {
			isSOA := r.findSoa(ans) != nil

			if !isSOA {
				dsok := r.verifyDS(ctx, q, isIPV6)
				if !dsok {
					ans.SetRcode(ans, dns.RcodeServerFailure)
					ans.Answer = nil
					ans.Extra = nil
					ans.Ns = nil
				}
			}
		}

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

	ans = r.cleanMsg(ans, req)
	return ans, nil
}

// https://www.cloudflare.com/it-it/dns/dnssec/how-dnssec-works/
func (r *Recursor) verifyDS(ctx context.Context, q dns.Question, isIPV6 bool) bool {
	name := q.Name
	end := false

	next := func(n string) (string, bool) {
		var i int
		i, end = dns.NextLabel(n, 0)
		name = dns.Fqdn(n[i:])
		return name, end
	}

	for {
		var ds *dns.DS
		// servers := getRootServers()
		if name == "." {
			// DS is root DS
			k, _ := dns.NewRR(rootKeys[0])
			key := k.(*dns.DNSKEY)
			ds = key.ToDS(dns.DH)
		} else {
			// resolve for DS
			dsreq := new(dns.Msg)
			dsreq.SetQuestion(name, dns.TypeDS)

			resp, _, err := r.resolveNS(ctx, dsreq, isIPV6, 0)
			if err != nil {
				return false
			}
			// servers = s

			if resp != nil && r.findSoa(resp) != nil {
				name, end = next(name)
				if end {
					return true
				}
				continue
			}

			dsans, err := r.resolve(r.newContext(ctx), dsreq, isIPV6)
			if err != nil {
				return false
			}
			dss := utils.MsgExtractByType(dsans, dns.TypeDS, name)

			if len(dss) == 0 {
				// No DS. Search into the upper zone
				name, end = next(name)
				if end {
					return true
				}
				continue
			}

			ds = dss[0].(*dns.DS)
		}

		// get keys
		kreq := new(dns.Msg)
		kreq.SetQuestion(name, dns.TypeDNSKEY)

		// this is not part of a previous recursion, I need to start a new context here
		// to reset the recursorContext as a fresh query
		kans, err := r.resolve(r.newContext(ctx), kreq, isIPV6)
		if err != nil {
			return false
		}
		keys := utils.MsgExtractByType(kans, dns.TypeDNSKEY, name)
		if len(keys) == 0 {
			log.Print(kans)
		}

		// keys := r.getDNSKEY(ctx, name, isIPV6, servers)

		// verify keys against DS
		verified := false
		for _, krr := range keys {
			key := krr.(*dns.DNSKEY)

			if ds != nil && ds.KeyTag == key.KeyTag() {
				pds := key.ToDS(ds.DigestType)
				if pds.Digest == ds.Digest {
					verified = true
					break
				}
			}
		}
		if verified {
			log.Debug().
				Str("q", name).
				Str("ds-name", ds.Header().Name).
				Msg("[dnssec] DS verified")
		} else {
			log.Debug().
				Str("q", name).
				Bool("has-ds", ds != nil).
				Bool("has-keys", len(keys) > 0).
				Msg("[dnssec] DS error: failed")
			return false
		}

		if end {
			return true
		}
		name, end = next(name)

		// var i int
		// i, end = dns.NextLabel(name, 0)
		// name = dns.Fqdn(name[i:])
	}
}

func (r *Recursor) cleanMsg(ans *dns.Msg, req *dns.Msg) *dns.Msg {
	// return ans
	q := req.Question[0]

	cleaned := ans.Copy()
	cleaned.Answer = []dns.RR{}
	cleaned.Ns = []dns.RR{}

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
			continue
		}
		if rr.Header().Rrtype == dns.TypeSOA {
			cleaned.Ns = append(cleaned.Ns, rr)
			continue
		}
		if opt != nil && opt.Do() {
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

	searchIp := func(e dns.RR, ns string) bool {
		ret := false
		switch e.Header().Rrtype {
		case dns.TypeA:
			ret = true
			a := e.(*dns.A)
			servers.List = append(servers.List, &nsServer{
				Addr:    a.A.String(),
				Fqdn:    ns,
				Version: pigdns.FamilyIPv4,
				TTL:     a.Hdr.Ttl,
			})
		case dns.TypeAAAA:
			ret = true
			aaaa := e.(*dns.AAAA)
			servers.List = append(servers.List, &nsServer{
				Addr:    aaaa.AAAA.String(),
				Fqdn:    ns,
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
			searchIp(e, ns.Ns)
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
			ipFound = searchIp(e, ns.Ns)
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
			searchIp(e, ns)
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
		nsReq := new(dns.Msg)
		nsReq.SetQuestion(zone, dns.TypeNS)
		nsq := nsReq.Question[0]
		cacheKey := fmt.Sprintf("%s_%d_%d", nsq.Name, nsq.Qtype, nsq.Qclass)
		resp, _ := r.ansCache.Get(cacheKey)
		if err != nil {
			return nil, cached, nil
		}
		return resp, cached, nil
	}

	// run recursively here. the recursion will end when we will
	// encounter the root zone
	resp, rservers, err := r.resolveNS(ctx, req, isIPV6, i)
	if err != nil {
		return resp, nil, err
	}

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(zone, dns.TypeNS)

	nsq := nsReq.Question[0]
	cacheKey := fmt.Sprintf("%s_%d_%d", nsq.Name, nsq.Qtype, nsq.Qclass)
	resp, err = r.ansCache.Get(cacheKey)
	if err != nil {
		qr := newQueryRacer(rservers, nsReq, isIPV6)
		resp, err = qr.run()
		if err != nil {
			return resp, nil, err
		}

		r.ansCache.Set(cacheKey, resp)
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
	isSOA := false
	soa := new(dns.Msg)
	soa.SetRcode(resp, resp.Rcode)

	for _, rr := range resp.Ns {
		switch rr.(type) {
		case *dns.NSEC, *dns.NSEC3, *dns.RRSIG:
			soa.Ns = append(resp.Ns, rr)
		case *dns.SOA:
			soa.Ns = append(soa.Ns, rr)
			isSOA = true
		}
	}
	if isSOA {
		return soa
	}

	return nil
}

func (r *Recursor) getDNSKEY(ctx context.Context, zone string, isIPV6 bool, servers *authServers) []dns.RR {
	req := new(dns.Msg)
	req.SetQuestion(zone, dns.TypeDNSKEY)

	q := req.Question[0]
	cacheKey := fmt.Sprintf("%s_%d_%d", q.Name, q.Qtype, q.Qclass)

	// try to get the answer from cache if we have it
	cached, cacheErr := r.ansCache.Get(cacheKey)
	if cacheErr == nil {
		return utils.MsgExtractByType(cached, dns.TypeDNSKEY, "")
	}

	keys := []dns.RR{}

	// _, servers, err := r.resolveNS(ctx, req, isIPV6, 0)
	// log.Print(servers.String())
	qr := newQueryRacer(servers, req, isIPV6)
	resp, err := qr.run()
	if err != nil {
		r.ansCache.Set(cacheKey, resp)
		return keys
	}

	keys = utils.MsgExtractByType(resp, dns.TypeDNSKEY, "")
	if len(keys) > 0 {
		r.ansCache.Set(cacheKey, resp)
	}
	return keys
}

func (r *Recursor) verifyRRSIG(ctx context.Context, ans *dns.Msg, q dns.Question, servers *authServers, isIPV6 bool) bool {

	rrsigs := utils.MsgExtractByType(ans, dns.TypeRRSIG, "")
	// log.Print(rrsigs)

	var sig *dns.RRSIG
	verified := false

	if len(rrsigs) == 0 {
		// nothing to verify
		return true
	}

	for _, rrsig := range rrsigs {
		sig = rrsig.(*dns.RRSIG)
		keys := r.getDNSKEY(ctx, sig.SignerName, isIPV6, servers)

		errors := 0
		for _, krr := range keys {
			key := krr.(*dns.DNSKEY)
			rrset := utils.MsgExtractByType(ans, sig.TypeCovered, q.Name)
			if len(rrset) == 0 {
				continue
			}
			err := sig.Verify(key, rrset)
			if err == nil {
				verified = true
				// break
			} else {
				errors++
			}
		}
		if errors == 0 {
			// nothing to verify
			verified = true
		}
	}

	if verified {
		if sig != nil {
			log.Debug().
				Str("q", q.Name).
				Str("signer", sig.SignerName).
				Msg("[dnssec] verified")
		}

		return true
	}

	log.Debug().
		Str("q", q.Name).
		Msg("[dnssec] not valid")
	return false
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

	cacheKey := fmt.Sprintf("%s_%d_%d", q.Name, q.Qtype, q.Qclass)
	cached, cacheErr := r.ansCache.Get(cacheKey)
	if cacheErr == nil {
		return cached, nil
	}

	resp, servers, err := r.resolveNS(ctx, req, isIPV6, 0)
	if err != nil {
		if err == errNoNSfound && resp != nil && len(resp.Ns) > 0 {
			soa := r.findSoa(resp)
			if soa != nil {
				r.ansCache.Set(cacheKey, soa)
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

	// TODO: investigate the 3 here
	// if I don't introduce it this will not work as expected (it should return a soa response)
	// Ex: dig @127.0.0.1 dprodmgd104.aa-rt.sharepoint.com
	// loop := 0
	// for loop < 3 {
	if len(ans.Answer) == 0 && len(ans.Ns) > 0 {
		// no asnwer from the previous query but we got nameservers instead
		// Get nameservers ips and try to query them
		servers, err = r.buildServers(ctx, ans, q.Name, isIPV6)
		if err != nil {
			// soa answer
			r.ansCache.Set(cacheKey, ans)
			return ans, nil
		}

		qr := newQueryRacer(servers, req, isIPV6)
		ans, err = qr.run()
		if err != nil {
			return nil, err
		}

		soa := r.findSoa(ans)
		if soa != nil {
			r.ansCache.Set(cacheKey, soa)
			return soa, nil
		}
	}
	// 	loop++
	// }

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
			rset := utils.MsgExtractByType(ansCopy, dns.TypeCNAME, "")
			if len(rset) > 0 {
				rr = rset[0]
			}
			if rr != nil && strings.EqualFold(rr.Header().Name, q.Name) {
				cname := rr.(*dns.CNAME)

				rc := ctx.Value(recursorContextKey).(*recursorContext)
				// prevents loops. if this ns was already in context in a previous
				// recursion, do not put it again in loop.
				if slices.Contains(rc.ToResolveList, cname.Target) {
					break
				}
				rc.ToResolveList = append(rc.ToResolveList, cname.Target)

				newReq := new(dns.Msg)
				newReq.SetQuestion(cname.Target, q.Qtype)

				// run a new query here to solve the CNAME
				// TODO: this one easily escape the blocklist.
				// it should traverse all the chain
				resp, err := r.Query(context.TODO(), newReq, isIPV6)
				if err == errRecursionMaxLevel {
					return nil, err
				}

				if err == nil {
					soa := r.findSoa(resp)
					if soa != nil {
						r.ansCache.Set(cacheKey, soa)
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

	// dnssec := r.verifyDNSSEC(ctx, ans, q, servers, isIPV6)
	dnssec := r.verifyRRSIG(ctx, ans, q, servers, isIPV6)
	if !dnssec {
		ans.SetRcode(ans, dns.RcodeServerFailure)
		ans.Answer = nil
		ans.Extra = nil
		ans.Ns = nil
	}

	r.ansCache.Set(cacheKey, ans)

	return ans, nil
}
