package recursor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

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
	// log.Printf("--> racing on")
	// for _, s := range qr.servers.List {
	// 	log.Printf("%s", s.String())
	// }
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

	worker := func(ns nsServer, wg *sync.WaitGroup) {
		defer wg.Done()
		req := qr.req.Copy()
		// log.Printf("||||| worker started for ns=%s, q=%s", ns.Addr, req.Question[0].String())
		ans, err := qr.queryNS(ctx, req, ns.withPort())

		if err == nil {
			ansCH <- ans
		} else {
			errCH <- err
		}

	}

	countErrors := 0
	var err error
	var ans *dns.Msg

	nextNSTimeout := 150 * time.Millisecond
	nextNSTimer := time.NewTimer(nextNSTimeout)
	defer nextNSTimer.Stop()

	for _, s := range qr.servers.List {
		if !qr.isIPV6 && s.Version == IPv6 {
			continue
		}

		wg.Add(1)
		nsc := nsServer{
			Addr:    s.Addr,
			Version: s.Version,
			TTL:     s.TTL,
		}
		go worker(nsc, &wg)
		nextNSTimer.Reset(nextNSTimeout)

		select {
		case <-nextNSTimer.C:
			continue
		case ans = <-ansCH:
			return ans, nil

		case err = <-errCH:
			countErrors++
			if countErrors == len(qr.servers.List) {
				return nil, err
			}
		}
	}

	select {
	case ans = <-ansCH:
		return ans, nil

	case err = <-errCH:
		return nil, err
	}
}
