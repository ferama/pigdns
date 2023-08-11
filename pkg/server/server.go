package server

import (
	"fmt"
	"strconv"
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
	port   int
	domain string
}

func NewServer(port int, domain string, enableResolver bool, datadir string) *Server {
	s := &Server{
		port:   port,
		domain: domain,
	}

	if domain != "" {
		s.setupDomainHandler()
	}
	if enableResolver {
		s.setupResolverHandler(datadir)
	}
	return s
}

func (s *Server) setupResolverHandler(datadir string) {
	var chain pigdns.Handler

	chain = &root.Handler{}
	chain = resolver.NewResolver(chain, datadir)
	chain = &collector.Handler{Next: chain}

	pigdns.Handle(".", chain)
}

func (s *Server) setupDomainHandler() {
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
	pigdns.Handle(dns.Fqdn(s.domain), chain)
}

func (s *Server) run(net string) {
	server := &dns.Server{
		Addr: ":" + strconv.Itoa(s.port),
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

	log.Info().Msgf("listening on ':%d'", s.port)

	wg.Wait()
}
