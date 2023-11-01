package recursor

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

var (
	errQueryRacerTimeout = errors.New("query timeout")
	errQnameEqNs         = errors.New("query name is equal to ns fqdn")
)

const (
	queryRacerTimeout = 5 * time.Second
	nextNSTimeout     = 50 * time.Millisecond
)

// the query racer, given a list of authoritative nameservers
// and a query, starts a run to get the result.
// It peeks one nameserver from the list and starts an exchange. It
// starts a timer also. If the timer expires, it starts a new exchange using
// the next nameserver. If one of the nameservers returns an answer, the run ends.
// If all of the nameserers give errors, the run ends
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

func (qr *queryRacer) queryNS(ctx context.Context, req *dns.Msg, ns *nsServer, zone string) (*dns.Msg, error) {
	q := req.Question[0]

	if q.Name == ns.Fqdn {
		return nil, errQnameEqNs
	}

	utils.RemoveOPT(req)
	req.SetEdns0(utils.MaxMsgSize, true)

	// If we are here, there is no cached answer. Do query upstream
	network := "udp"
	noEdnsTried := false
	for {
		client := &dns.Client{
			Timeout: dialTimeout,
			Net:     network,
		}

		log.Debug().
			Str("ns-ip", ns.Addr).
			Str("ns-fqdn", ns.Fqdn).
			Str("zone", zone).
			Str("q", q.Name).
			Str("type", dns.TypeToString[q.Qtype]).
			Msg("[recursor]")

		ans, _, err := client.ExchangeContext(ctx, req, ns.withPort())
		if err != nil {
			return nil, err
		}

		// if the server reply with FORMERR, retry with no edns
		if ans.Rcode == dns.RcodeFormatError && !noEdnsTried {
			utils.RemoveOPT(req)
			noEdnsTried = true
			continue
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
	ctx, cancel := context.WithCancel(context.TODO())

	qr.servers.RLock()
	ansCH := make(chan *dns.Msg, len(qr.servers.List))
	errCH := make(chan error, len(qr.servers.List))
	qr.servers.RUnlock()

	var wg sync.WaitGroup

	defer func() {
		cancel()

		go func() {
			wg.Wait()
			close(ansCH)
			close(errCH)
		}()
	}()

	worker := func(ns *nsServer, wg *sync.WaitGroup) {
		defer wg.Done()

		// Copy is needed here, to prevent race conditions
		ans, err := qr.queryNS(ctx, qr.req.Copy(), ns.Copy(), qr.servers.Zone)

		if err == nil {
			ansCH <- ans
		} else {
			errCH <- err
		}

	}

	countErrors := 0
	var err error
	var ans *dns.Msg

	nextNSTimer := time.NewTimer(nextNSTimeout)
	defer nextNSTimer.Stop()

	ipV6S := []*nsServer{}
	ipV4S := []*nsServer{}
	qr.servers.RLock()
	for _, s := range qr.servers.List {
		if s.Version == pigdns.FamilyIPv4 {
			ipV4S = append(ipV4S, s)
		} else {
			ipV6S = append(ipV6S, s)
		}
	}
	qr.servers.RUnlock()

	servers := ipV4S

	if qr.isIPV6 {
		// we can query the ipv6 nameservers too
		// put them into the head of the list
		servers = append(ipV6S, servers...)
	}

	for _, s := range servers {
		wg.Add(1)
		go worker(s, &wg)
		nextNSTimer.Reset(nextNSTimeout)

		select {
		case <-nextNSTimer.C:
			continue
		case ans = <-ansCH:
			return ans, nil

		case err = <-errCH:
			countErrors++
			qr.servers.RLock()
			// no more nameservers to query
			if countErrors == len(qr.servers.List) {
				qr.servers.RUnlock()
				return nil, err
			}
			qr.servers.RUnlock()
		}
	}

	// If I'm out of loop and I'm here is because all the timeout occurred
	// and I still don't have an answer so wait here for it
	for {
		select {
		case <-time.After(queryRacerTimeout):
			return nil, errQueryRacerTimeout
		case ans = <-ansCH:
			return ans, nil

		case err = <-errCH:
			countErrors++
			qr.servers.RLock()
			if countErrors == len(qr.servers.List) {
				qr.servers.RUnlock()
				// log.Print(qr.servers)
				return nil, err
			}
			qr.servers.RUnlock()
		}
	}
}
