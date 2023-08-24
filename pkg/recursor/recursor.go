package recursor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
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

	// getAnswer will be called recursively. the recustion
	// count cannot be greater than recursionMaxLevel
	recursionMaxLevel = 512
)

type Recursor struct {
	cache *recursorCache
}

func New(datadir string) *Recursor {
	r := &Recursor{}
	if datadir != "" {
		log.Printf("[recursor] enabling file based cache")
		r.cache = newRecursorCache(datadir)
	}
	return r
}

func (r *Recursor) Query(ctx context.Context, req *dns.Msg, isIPV6 bool) (*dns.Msg, error) {
	cc := &ResolverContext{
		RecursionCount: 0,
	}
	ctx = context.WithValue(ctx, ResolverContextKey, cc)

	nsaddr := r.getRootNS(isIPV6)
	ans, err := r.resolve(ctx, req, isIPV6, 1, nsaddr)
	if err != nil {
		return nil, err
	}

	utils.MsgSetupEdns(ans)

	return ans, nil
}

func (r *Recursor) resolveNSIPFromAns(ans *dns.Msg, isIPV6 bool) (string, error) {

	ipv4 := []net.IP{}
	ipv6 := []net.IP{}

	if ans.Authoritative {
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
	} else {
		if len(ans.Ns) == 0 {
			return "", errors.New("not NS record found")
		}
		n := rand.Intn(len(ans.Ns))
		rr := ans.Ns[n]
		if _, ok := rr.(*dns.NS); !ok {
			return "", errors.New("not a NS record")
		}
		ns := rr.(*dns.NS)

		for _, e := range ans.Answer {
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
	return "", errors.New("not ns record found")
}
func (r *Recursor) resolveNS(ctx context.Context, ans *dns.Msg, isIPV6 bool) (string, error) {
	res, err := r.resolveNSIPFromAns(ans, isIPV6)
	if err == nil {
		return res, err
	}

	n := rand.Intn(len(ans.Ns))
	rr := ans.Ns[n]
	if _, ok := rr.(*dns.NS); !ok {
		return "", errors.New("is not an NS record")
	}
	ns := rr.(*dns.NS)

	r1 := new(dns.Msg)
	r1.SetQuestion(dns.Fqdn(ns.Ns), dns.TypeA)

	nsaddr := r.getRootNS(isIPV6)
	resp, err := r.resolve(ctx, r1, isIPV6, 1, nsaddr)
	if err != nil {
		return "", err
	}
	return r.resolveNSIPFromAns(resp, isIPV6)
}

func (r *Recursor) resolve(ctx context.Context, req *dns.Msg, isIPV6 bool, depth int, nsaddr string) (*dns.Msg, error) {
	q := req.Question[0]
	labels := dns.SplitDomainName(q.Name)
	slices.Reverse(labels)

	l := labels[0:depth]

	slices.Reverse(l)
	fqdn := dns.Fqdn(strings.Join(l, "."))

	r1 := new(dns.Msg)
	r1.SetQuestion(fqdn, q.Qtype)

	ans, err := r.queryNS(r1, nsaddr)
	if err != nil {
		return nil, err
	}

	// log.Printf("auth: %v, fqdn: %s, ns: %s", ans.Authoritative, fqdn, ans.Ns)

	if !ans.Authoritative && len(ans.Ns) > 0 {
		// find the delegate nameserver address
		nsaddr, err := r.resolveNS(ctx, ans, isIPV6)
		if err != nil {
			return nil, err
		}
		// resolve using the new addr
		return r.resolve(ctx, req, isIPV6, depth+1, nsaddr)
	}

	if len(ans.Answer) == 0 && depth+1 <= len(labels) {
		// go deeper
		return r.resolve(ctx, req, isIPV6, depth+1, nsaddr)
	}
	haveAnswer := false
	for _, rr := range ans.Answer {
		if rr.Header().Name == q.Name && rr.Header().Rrtype == q.Qtype {
			haveAnswer = true
		}
	}
	if !haveAnswer {
		return nil, errors.New("no anwer found")
	}
	return ans, nil
}

func (r *Recursor) getRootNS(isIPV6 bool) string {
	var nsaddr string
	if isIPV6 {
		nsaddr = fmt.Sprintf("[%s]:53", getRootNSIPv6())
	} else {
		nsaddr = fmt.Sprintf("%s:53", getRootNSIPv4())
	}

	return nsaddr
}

func (r *Recursor) queryNS(req *dns.Msg, nsaddr string) (*dns.Msg, error) {
	haveCache := r.cache != nil

	q := req.Question[0]
	if haveCache {
		ans, cacheErr := r.cache.Get(q, nsaddr)
		if cacheErr == nil {
			return ans, nil
		}
	}

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
