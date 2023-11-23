package recursor

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ferama/pigdns/pkg/metrics"
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

	errNameserversLoop = errors.New("nameservers loop detected")
)

type contextKey string

const recursorContextKey contextKey = "recursor-context"

type recursorContext struct {
	sync.RWMutex

	RecursionCount int
	ToResolveList  []string
}

const (
	// timeout until error
	dialTimeout = 2 * time.Second

	// how deeply we will search for cnames and nameservers
	chainMaxDeep = 16

	// resolver will be called recursively. the recustion
	// count cannot be greater than resolverMaxLevel
	resolverMaxLevel = 24
	// resolverMaxLevel = 16

	ansCacheName = "anscache"
	nsCacheName  = "nscache"
)

type Recursor struct {
	ansCache *ansCache
	nsCache  *nsCache

	rootkeys []dns.RR

	oneInFlight *oneinflight.OneInFlight
}

func New(datadir string, cacheSize int) *Recursor {
	ansCacheSize := cacheSize * 75 / 100
	nsCacheSize := cacheSize * 25 / 100

	r := &Recursor{
		oneInFlight: oneinflight.New(),
		ansCache:    newAnsCache(filepath.Join(datadir, "cache", "addr"), ansCacheName, ansCacheSize),
		nsCache:     newNSCache(filepath.Join(datadir, "cache", "ns"), nsCacheName, nsCacheSize),
	}

	metrics.Instance().RegisterCache(ansCacheName)
	metrics.Instance().RegisterCache(nsCacheName)

	metrics.Instance().GetCacheCapacityMetric(ansCacheName).Set(float64(ansCacheSize))
	metrics.Instance().GetCacheCapacityMetric(nsCacheName).Set(float64(nsCacheSize))

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

	cached, cacheErr := r.ansCache.Get(reqKey)
	if cacheErr == nil {
		ans := r.cleanMsg(cached, req)

		pc := ctx.Value(pigdns.PigContextKey).(*pigdns.PigContext)
		pc.CacheHit = true
		return ans, nil
	}

	// run the query (only once concurrently
	// against the upstream nameservers)
	type retvalue struct {
		Ans *dns.Msg
		Err error
	}
	tmp := r.oneInFlight.Run(reqKey, func(params ...any) any {
		ans, err := r.resolve(ctx, req, isIPV6)

		if err == nil {
			if ans.AuthenticatedData {
				dsok := r.verifyDS(ctx, ans, q, isIPV6)
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
	pc := ctx.Value(pigdns.PigContextKey).(*pigdns.PigContext)
	pc.Rcode = ans.Rcode
	return ans, nil
}

// https://www.cloudflare.com/it-it/dns/dnssec/how-dnssec-works/
func (r *Recursor) verifyDS(ctx context.Context, ans *dns.Msg, q dns.Question, isIPV6 bool) bool {
	// return true

	name := q.Name

	// TODO: it make sense?
	if utils.IsArpa(name) {
		utils.MsgSetAuthenticated(ans, false)
		return true
	}

	end := false

	next := func(n string) (string, bool) {
		var i int
		i, end = dns.NextLabel(n, 0)
		name = dns.Fqdn(n[i:])
		return name, end
	}

	for {
		var ds *dns.DS
		if name == "." {
			// DS is root DS
			k, _ := dns.NewRR(rootKeys[0])
			key := k.(*dns.DNSKEY)
			ds = key.ToDS(dns.DH)
		} else {
			// resolve for DS
			dsreq := new(dns.Msg)
			dsreq.SetQuestion(name, dns.TypeDS)

			resp, _, err := r.resolveNS(ctx, dsreq.Question[0], isIPV6, 0)
			if err != nil {
				return false
			}

			if resp != nil && r.findSoa(resp) != nil {
				name, end = next(name)
				if end {
					return true
				}
				continue
			}

			dsans, err := r.resolve(r.newContext(ctx), dsreq, isIPV6)
			if err != nil {
				// if error is nameserversLoop, no DS record exists
				return err == errNameserversLoop
			}

			nsec3Set := utils.MsgExtractByType(dsans, dns.TypeNSEC3, "")
			if len(nsec3Set) > 0 {
				secerr := nsecVerifyNODATA(dsans, nsec3Set)
				if secerr != nil {
					log.Error().Msg(secerr.Error())
					return false
				}
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

func (r *Recursor) searchNSIp(e dns.RR, ns string, servers *authServers) bool {
	servers.Lock()
	defer servers.Unlock()

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

func (r *Recursor) buildServers(ctx context.Context, ans *dns.Msg, zone string, currServers *authServers, isIPV6 bool) (*authServers, error) {
	servers := &authServers{
		Zone: zone,
	}

	toResolve := []string{}

	if len(ans.Ns) == 0 && len(ans.Answer) == 0 {
		return nil, errNoNSfound
	}

	ipFound := false

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
			r.searchNSIp(e, ns.Ns, servers)
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
			ipFound = r.searchNSIp(e, ns.Ns, servers)
		}

		if !ipFound {
			// is a ns record without an extra section
			// put in a toResolve list and handle it later if needed
			toResolve = append(toResolve, ns.Ns)
		}
	}

	// Resolve Extra Servers
	extraServers := &authServers{
		Zone: zone,
	}

	r.resolveExtraNs(ctx, toResolve, zone, extraServers, isIPV6)
	extraServers.RLock()
	if len(extraServers.List) > 0 {
		servers.RLock()
		servers.List = append(servers.List, extraServers.List...)

		// TODO: disabled for now. Add a test if it is needed
		//
		// if currServers != nil {
		// 	currServers.Lock()
		// 	servers.List = append(servers.List, currServers.List...)
		// 	currServers.Unlock()
		// }

		servers.RUnlock()
		extraServers.RUnlock()
	}

	// if we are here we don't have any place to search anymore
	servers.RLock()
	defer servers.RUnlock()
	if len(servers.List) == 0 {
		return nil, errNoNSfound
	}
	return servers, nil
}

func (r *Recursor) resolveExtraNs(ctx context.Context, toResolve []string, zone string, servers *authServers, isIPV6 bool) {
	rc := ctx.Value(recursorContextKey).(*recursorContext)
	// if we have NS not resolved in Extra section, resolve them
	for _, ns := range toResolve {
		// prevents loops. if this ns was already in context in a previous
		// recursion, do not put it again in loop.
		rc.Lock()
		if slices.Contains(rc.ToResolveList, ns) {
			rc.Unlock()
			break
		}
		rc.ToResolveList = append(rc.ToResolveList, ns)
		rc.Unlock()

		// get the A record
		ra := new(dns.Msg)
		ra.SetQuestion(ns, dns.TypeA)
		rans, err := r.resolve(ctx, ra, isIPV6)
		if err != nil {
			if err == errRecursionMaxLevel {
				break
			}
			continue
		}
		for _, e := range rans.Answer {
			r.searchNSIp(e, ns, servers)
		}

		// get the AAAA record
		go func(ctx context.Context, ns string) {
			// reset the recursion count, we are starting a new journey here
			rc := ctx.Value(recursorContextKey).(*recursorContext)
			rc.Lock()
			rc.RecursionCount = 0
			rc.Unlock()
			ctx = context.WithValue(ctx, recursorContextKey, rc)

			raaaa := new(dns.Msg)
			raaaa.SetQuestion(ns, dns.TypeAAAA)
			raaaans, err := r.resolve(ctx, raaaa, isIPV6)
			if err != nil {
				return
			}

			s, err := r.nsCache.Get(zone)
			if err == nil {
				servers.Lock()
				servers.List = s.List
				servers.Unlock()
			}
			haveNew := false
			for _, e := range raaaans.Answer {
				haveNew = r.searchNSIp(e, ns, servers)
			}
			if haveNew {
				// update cache including the discovered ipv6 addresses
				r.nsCache.Set(servers)
			}
		}(ctx, ns)
	}
}

// resolveNS builds an authServers object filling it with zone and resolved related nameservers ips
// it returns in order:
// *dns.Msg the latest response from a queried NS server if any
// *authServers the authServers object
// error
func (r *Recursor) resolveNS(ctx context.Context, q dns.Question, isIPV6 bool, offset int) (*dns.Msg, *authServers, error) {
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
	resp, rservers, err := r.resolveNS(ctx, q, isIPV6, i)
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

		// take advantage of the extra secion and store some ips into cache
		// if any
		types := []uint16{
			dns.TypeA,
			dns.TypeAAAA,
		}

		for _, t := range types {
			arr := utils.MsgExtractByType(resp, t, "")
			for _, rr := range arr {
				ck := fmt.Sprintf("%s_%d_%d", rr.Header().Name, t, rr.Header().Class)
				m := new(dns.Msg)
				m.Answer = append(m.Answer, rr)
				r.ansCache.Set(ck, m)
			}
		}

		r.ansCache.Set(cacheKey, resp)
	}

	servers, err := r.buildServers(ctx, resp, zone, rservers, isIPV6)
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

	// Add parent servers too
	serversFqdns := []string{}
	for _, s := range servers.List {
		serversFqdns = append(serversFqdns, s.Fqdn)
	}
	if dns.CountLabel(servers.Zone) > 2 {
		for _, i := range rservers.List {
			if !slices.Contains(serversFqdns, i.Fqdn) {
				servers.List = append(servers.List, i)
			}
		}
	}

	// severs.Zone could be different from zone if
	// servers was set to rservers above. In that case
	// we don't need to update cache
	if err == nil && servers.Zone == zone {
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

func (r *Recursor) getDNSKEY(ctx context.Context, zone string, isIPV6 bool) []dns.RR {
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

	_, rservers, err := r.resolveNS(ctx, q, isIPV6, 0)
	if err != nil {
		return keys
	}
	qr := newQueryRacer(rservers, req, isIPV6)
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
	// return true
	if utils.IsArpa(q.Name) {
		// TODO: it make sense?

		utils.MsgSetAuthenticated(ans, false)
		return true
	}

	rrsigs := utils.MsgExtractByType(ans, dns.TypeRRSIG, "")

	var sig *dns.RRSIG
	verified := false

	if len(rrsigs) == 0 {
		// nothing to verify
		utils.MsgSetAuthenticated(ans, false)
		return true
	}

	for _, rrsig := range rrsigs {
		sig = rrsig.(*dns.RRSIG)
		keys := r.getDNSKEY(ctx, sig.SignerName, isIPV6)

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

		utils.MsgSetAuthenticated(ans, true)
		return true
	}

	log.Debug().
		Str("q", q.Name).
		Msg("[dnssec] not valid")

	utils.MsgSetAuthenticated(ans, false)
	return false
}

func (r *Recursor) resolve(ctx context.Context, req *dns.Msg, isIPV6 bool) (*dns.Msg, error) {
	rc := ctx.Value(recursorContextKey).(*recursorContext)
	rc.Lock()
	rc.RecursionCount++
	if rc.RecursionCount >= resolverMaxLevel {
		log.Printf("///////// RecursionLimit %d", rc.RecursionCount)
		rc.Unlock()
		return nil, errRecursionMaxLevel
	}
	rc.Unlock()
	ctx = context.WithValue(ctx, recursorContextKey, rc)

	q := req.Question[0]

	cacheKey := fmt.Sprintf("%s_%d_%d", q.Name, q.Qtype, q.Qclass)
	cached, cacheErr := r.ansCache.Get(cacheKey)
	if cacheErr == nil {
		return cached, nil
	}

	nsResp, servers, err := r.resolveNS(ctx, q, isIPV6, 0)
	if err != nil {
		if err == errNoNSfound && nsResp != nil && len(nsResp.Ns) > 0 {
			soa := r.findSoa(nsResp)
			if soa != nil {
				dnssec := r.verifyRRSIG(ctx, soa, q, servers, isIPV6)
				if !dnssec {
					soa.SetRcode(soa, dns.RcodeServerFailure)
					soa.Answer = nil
					soa.Extra = nil
					soa.Ns = nil
				}
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

	maxNsDepth := chainMaxDeep
	for len(ans.Answer) == 0 && len(ans.Ns) > 0 {
		maxNsDepth--
		// prevents death loop
		if maxNsDepth == 0 {
			break
		}
		// no asnwer from the previous query but we got nameservers instead
		// Get nameservers ips and try to query them
		nextServers, err := r.buildServers(ctx, ans, q.Name, nil, isIPV6)
		if err != nil {
			if err != errNoNSfound {
				// soa answer
				r.ansCache.Set(cacheKey, ans)
				return ans, nil
			}
		}
		if nextServers == nil {
			return ans, nil
		}

		// detect loops
		newFqdns := false
		newAddrs := false
		nsFqdns := []string{}
		nsAddr := []string{}

		nextServers.RLock()
		for _, i := range nextServers.List {
			nsFqdns = append(nsFqdns, i.Fqdn)
			nsAddr = append(nsAddr, i.Addr)
		}
		nextServers.RUnlock()

		servers.RLock()
		for _, j := range servers.List {
			if !slices.Contains(nsFqdns, j.Fqdn) {
				newFqdns = true
			}
			if !slices.Contains(nsAddr, j.Addr) {
				newAddrs = true
			}
		}
		servers.RUnlock()

		if !newFqdns || !newAddrs {
			return nil, errNameserversLoop
		}

		// no loop detected, use the nextServers
		// servers = nextServers
		servers.Lock()
		nextServers.RLock()
		servers.List = nextServers.List
		nextServers.RUnlock()
		servers.Unlock()

		qr := newQueryRacer(servers, req, isIPV6)
		ans, err = qr.run()
		if err != nil {
			return nil, err
		}

		soa := r.findSoa(ans)
		if soa != nil {
			dnssec := r.verifyRRSIG(ctx, soa, q, servers, isIPV6)
			if !dnssec {
				soa.SetRcode(soa, dns.RcodeServerFailure)
				soa.Answer = nil
				soa.Extra = nil
				soa.Ns = nil
			}

			r.ansCache.Set(cacheKey, soa)
			return soa, nil
		}
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
		maxLoop := chainMaxDeep
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
				rc.Lock()
				rc.ToResolveList = append(rc.ToResolveList, cname.Target)
				rc.Unlock()

				newReq := new(dns.Msg)
				newReq.SetQuestion(cname.Target, q.Qtype)

				// run a new query here to solve the CNAME
				// this must traverse all the chain otherwise
				// it could easily escape the blocklist
				resp, err := pigdns.QueryIntenal(ctx, newReq, isIPV6)

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

	dnssec := r.verifyRRSIG(ctx, ans, q, servers, isIPV6)
	if !dnssec {
		ans.SetRcode(ans, dns.RcodeServerFailure)
		ans.Answer = nil
		ans.Extra = nil
		ans.Ns = nil
	}

	if nsResp != nil {
		soa := r.findSoa(nsResp)
		if soa == nil {
			nsec3Set := utils.MsgExtractByType(nsResp, dns.TypeNSEC3, "")
			if len(nsec3Set) > 0 && len(nsResp.Ns) > 0 {
				secerr := nsecVerifyDelegation(nsResp.Ns[0].Header().Name, nsec3Set)
				if secerr != nil {
					return nil, secerr
				}
				log.Debug().
					Msg("[dnssec] NSEC3 verified")
			}
		}
	}

	r.ansCache.Set(cacheKey, ans)
	return ans, nil
}
