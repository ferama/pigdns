package recursor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
)

type queryRacer struct {
	servers *authServers
	req     *dns.Msg
	isIPV6  bool
}

func newQueryRacer(servers *authServers, req *dns.Msg, isIPV6 bool) *queryRacer {
	q := &queryRacer{
		servers: servers,
		req:     req,
		isIPV6:  isIPV6,
	}
	return q
}

func (qr *queryRacer) queryNS(ctx context.Context, req *dns.Msg, nsaddr string) (*dns.Msg, error) {
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

		ans, _, err := client.ExchangeContext(ctx, req, nsaddr)
		if err != nil {
			return nil, err
		}
		if slices.Contains(rootNSIPv4, tmp.Addr().String()) || slices.Contains(rootNSIPv6, tmp.Addr().String()) {
			log.Printf("[recursor] queried ROOT ns=%s q=%s t=%s", tmp, qname, dns.TypeToString[q.Qtype])
		} else {
			log.Printf("[recursor] queried ns=%s q=%s t=%s", nsaddr, qname, dns.TypeToString[q.Qtype])
		}

		if !ans.Truncated {
			return ans, nil
		}
		if network == "tcp" {
			return nil, errors.New("cannot get a non truncated answer")
		}
		log.Printf("[recuror] resp truncated. trying tcp...")
		network = "tcp"
	}
}

func (qr *queryRacer) run() (*dns.Msg, error) {
	log.Printf("--> racing on")
	for _, s := range qr.servers.List {
		log.Printf("%s", s.String())
	}
	ctx, cancel := context.WithCancel(context.TODO())

	ansCH := make(chan *dns.Msg, len(qr.servers.List))
	errCH := make(chan error, len(qr.servers.List))

	var wg sync.WaitGroup

	defer func() {
		cancel()

		go func() {
			wg.Wait()
			close(ansCH)
			close(errCH)
		}()
	}()

	for _, s := range qr.servers.List {
		if !qr.isIPV6 && s.Version == IPv6 {
			continue
		}
		wg.Add(1)
		go func(ns nsServer) {
			defer wg.Done()
			ans, err := qr.queryNS(ctx, qr.req.Copy(), ns.withPort())

			if err == nil {
				ansCH <- ans
			} else {
				errCH <- err
			}

		}(s)
	}

	errors := 0
	var err error
	var ans *dns.Msg

	shouldBreak := false
	for {
		if shouldBreak {
			break
		}
		select {
		case ans = <-ansCH:
			// log.Printf("==== got ans")
			return ans, nil

		case err = <-errCH:
			// log.Printf("==== got err")
			errors++
			if errors == len(qr.servers.List) {
				// cancel()
				shouldBreak = true
			}
		}
	}

	return nil, err
}
