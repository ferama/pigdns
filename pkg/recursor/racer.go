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
)

const (
	queryRacerTimeout = 10 * time.Second
	nextNSTimeout     = 150 * time.Millisecond
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

func (qr *queryRacer) queryNS(ctx context.Context, req *dns.Msg, ns *nsServer) (*dns.Msg, error) {
	q := req.Question[0]

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

	worker := func(ns *nsServer, wg *sync.WaitGroup) {
		defer wg.Done()
		// Copy is needed here, to prevent race conditions
		ans, err := qr.queryNS(ctx, qr.req.Copy(), ns.Copy())

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

	for _, s := range qr.servers.List {
		if !qr.isIPV6 && s.Version == pigdns.FamilyIPv6 {
			continue
		}

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
			// no more nameservers to query
			if countErrors == len(qr.servers.List) {
				return nil, err
			}
		}
	}

	// If I'm out of loop and I'm here is because all the timeout occurred
	// and I still don't have an answer so wait here for it
	select {
	case <-time.After(queryRacerTimeout):
		return nil, errQueryRacerTimeout
	case ans = <-ansCH:
		return ans, nil

	case err = <-errCH:
		return nil, err
	}
}
