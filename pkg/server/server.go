package server

import (
	"context"
	"fmt"
	"sync"

	"github.com/ferama/pigdns/pkg/handlers/acmec"
	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/handlers/regexip"
	"github.com/ferama/pigdns/pkg/handlers/resolver"
	"github.com/ferama/pigdns/pkg/handlers/root"
	"github.com/ferama/pigdns/pkg/handlers/zone"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type Server struct {
	listenAddress string
	domain        string
}

func NewServer(listenAddress string, domain string, enableResolver bool, datadir string) *Server {
	s := &Server{
		listenAddress: listenAddress,
		domain:        domain,
	}

	if domain != "" {
		h := s.buildDomainHandler()
		pigdns.Handle(dns.Fqdn(s.domain), h)
	}
	if enableResolver {
		h := s.buildResolverHandler(datadir)
		pigdns.Handle(".", h)
	}

	return s
}

func (s *Server) buildResolverHandler(datadir string) pigdns.Handler {
	var chain pigdns.Handler

	// chain = &root.Handler{}
	chain = pigdns.HandlerFunc(func(ctx context.Context, r *pigdns.Request) {
		m := new(dns.Msg)
		m.Authoritative = false
		m.Rcode = dns.RcodeServerFailure
		if ctx.Value(collector.CollectorContextKey) != nil {
			cc := ctx.Value(collector.CollectorContextKey).(*collector.CollectorContext)
			cc.AnweredBy = "failure"
		}
		r.Reply(m)
	})
	chain = resolver.NewResolver(chain, datadir)
	chain = &collector.Handler{Next: chain}

	return chain
}

func (s *Server) buildDomainHandler() pigdns.Handler {
	// the first handler that write back to the client calling
	// w.WriteMsg(m) win. No other handler can write back anymore
	// Chain rings are called in reverse order
	var chain pigdns.Handler

	zoneFilePath := viper.GetString(utils.ZoneFileFlag)

	// leaf handler (is the latest one)
	chain = &root.Handler{}

	chain = &regexip.Handler{Next: chain}
	if zoneFilePath != "" {
		chain = zone.New(chain)
	}
	certmanEnable := viper.GetBool(utils.CertmanEnableFlag)
	if certmanEnable {
		chain = &acmec.Handler{Next: chain}
	}

	chain = &collector.Handler{Next: chain}
	return chain
}

func (s *Server) run(net string) {
	server := &dns.Server{
		Addr: s.listenAddress,
		Net:  net,
	}

	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatal().Msg(fmt.Sprintf("failed to start server: %s\n ", err.Error()))
	}
}

func (s *Server) Start() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		s.run("udp")
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		s.run("tcp")
		wg.Done()
	}()

	log.Info().Msgf("listening on ':%d'", s.listenAddress)

	wg.Wait()
}
