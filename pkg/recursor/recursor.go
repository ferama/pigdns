package recursor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

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

	// nsaddr := r.getRootNS(isIPV6)

	// labels := dns.SplitDomainName(req.Question[0].Name)
	// root := labels[len(labels)-1]

	// log.Printf("%s", root)
	// r1 := new(dns.Msg)
	// r1.SetQuestion(dns.Fqdn(root), dns.TypeA)

	// ns, err := r.getAnswer(ctx, r1, nsaddr, false)
	// log.Printf("root ns: %s, err: %s", ns, err)
	return r.resolve(ctx, req, isIPV6, 0)
}

func (r *Recursor) resolve(ctx context.Context, req *dns.Msg, isIPV6 bool, depth int) (*dns.Msg, error) {
	labels := dns.SplitDomainName(req.Question[0].Name)

	var nsaddr string
	if depth == 0 {
		nsaddr = r.getRootNS(isIPV6)
	}

	l := labels[:len(labels)-depth]
	fqdn := dns.Fqdn(strings.Join(l, "."))
	log.Printf("%s", fqdn)

	r1 := new(dns.Msg)
	r1.SetQuestion(fqdn, dns.TypeA)

	ans, err := r.queryNS(r1, nsaddr)
	if err != nil {
		return nil, err
	}
	ans = r.resolveAnswer(ans, dns.TypeA)
	log.Printf("%s", ans)

	return ans, nil
}

func (r *Recursor) resolveAnswer(ans *dns.Msg, typ uint16) *dns.Msg {
	m := new(dns.Msg)
	for _, rr := range ans.Answer {
		if rr.Header().Rrtype == typ {
			m.Answer = append(m.Answer, rr)
		}
	}
	for _, rr := range ans.Extra {
		if rr.Header().Rrtype == typ {
			m.Answer = append(m.Answer, rr)
		}
	}
	return m
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
