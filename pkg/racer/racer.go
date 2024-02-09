package racer

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
	// timeout until error
	dialTimeout = 2 * time.Second

	queryRacerTimeout = 2 * time.Second
	nextNSTimeout     = 100 * time.Millisecond
)

// the query racer, given a list of authoritative nameservers
// and a query, starts a run to get the result.
// It peeks one nameserver from the list and starts an exchange. It
// starts a timer also. If the timer expires, it starts a new exchange using
// the next nameserver. If one of the nameservers returns an answer, the run ends.
// If all of the nameserers give errors, the run ends
type queryRacer struct {
	servers []NS
	req     *dns.Msg
	isIPV6  bool

	RecursionDesired bool
}

func NewQueryRacer(servers []NS, req *dns.Msg, isIPV6 bool) *queryRacer {
	q := &queryRacer{
		servers:          servers,
		req:              req,
		isIPV6:           isIPV6,
		RecursionDesired: false,
	}

	return q
}

func (qr *queryRacer) queryNS(ctx context.Context, req *dns.Msg, ns NS) (*dns.Msg, error) {
	q := req.Question[0]

	st := time.Now()
	defer func() {
		l := time.Since(st)
		log.Debug().
			Str(".q", q.Name).
			// Str("zone", zone).
			Str("ns-fqdn", ns.Fqdn).
			Str("ns-addr", ns.Addr).
			Str("t", l.Round(1*time.Millisecond).String()).
			Str("type", dns.TypeToString[q.Qtype]).
			Msg("[racer]")

	}()

	utils.MsgRemoveOPT(req)
	// I need the do flag set here, otherwise no RRSIG record will be returned
	req.SetEdns0(utils.MaxMsgSize, true)

	// we do not want and to not expect recursive responses
	// If we do not specify the value here, some servers will block us
	req.RecursionDesired = qr.RecursionDesired

	// If we are here, there is no cached answer. Do query upstream
	network := "udp"
	noEdnsTried := false
	for {
		client := &dns.Client{
			Timeout: dialTimeout,
			Net:     network,
		}

		ans, _, err := client.ExchangeContext(ctx, req, ns.withPort())
		if err != nil {
			return nil, err
		}

		// if the server reply with FORMERR, retry with no edns
		if ans.Rcode == dns.RcodeFormatError && !noEdnsTried {
			utils.MsgRemoveOPT(req)
			noEdnsTried = true
			continue
		}

		if !ans.Truncated {
			return ans, nil
		}
		if network == "tcp" {
			return nil, errors.New("cannot get a non truncated answer")
		}
		log.Printf("[racer] resp truncated. trying tcp...")
		network = "tcp"
	}
}

func (qr *queryRacer) Run() (*dns.Msg, error) {
	ctx, cancel := context.WithCancel(context.TODO())

	// qr.servers.RLock()
	ansCH := make(chan *dns.Msg, len(qr.servers))
	errCH := make(chan error, len(qr.servers))
	// qr.servers.RUnlock()

	var wg sync.WaitGroup

	defer func() {
		cancel()

		go func() {
			wg.Wait()
			close(ansCH)
			close(errCH)
		}()
	}()

	worker := func(ns NS, wg *sync.WaitGroup) {
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

	defer func() {
		if ans != nil {
			// always remove the do flag here. It will eventually set
			// after DNSSEC verification
			utils.MsgSetAuthenticated(ans, false)
		}
	}()

	nextNSTimer := time.NewTimer(nextNSTimeout)
	defer nextNSTimer.Stop()

	ipV6S := []NS{}
	ipV4S := []NS{}
	for _, s := range qr.servers {
		if s.Version == pigdns.FamilyIPv4 {
			ipV4S = append(ipV4S, s)
		} else {
			ipV6S = append(ipV6S, s)
		}
	}

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
			if !utils.AnsIsError(ans) {
				return ans, nil
			}
			countErrors++

		case err = <-errCH:
			countErrors++
			// no more nameservers to query
			if countErrors == len(qr.servers) {
				return nil, err
			}
		}
	}

	// If I'm out of loop and I'm here is because all the timeout occurred
	// and I still don't have an answer so wait here for it
	for {
		select {
		case <-time.After(queryRacerTimeout):
			return nil, errQueryRacerTimeout
		case ans = <-ansCH:
			if !utils.AnsIsError(ans) {
				return ans, nil
			}
			countErrors++

		case err = <-errCH:
			// return nil, err
			countErrors++
			if countErrors == len(qr.servers) {
				return nil, err
			}
		}
	}
}
