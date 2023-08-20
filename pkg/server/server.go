package server

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

type Server struct {
	listenAddress string
	mux           *dns.ServeMux
}

func NewServer(mux *dns.ServeMux, listenAddress string) *Server {
	s := &Server{
		listenAddress: listenAddress,
		mux:           mux,
	}
	return s
}

func (s *Server) run(net string) {
	server := &dns.Server{
		Addr:    s.listenAddress,
		Net:     net,
		Handler: s.mux,
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

	log.Info().Msgf("listening on '%s'", s.listenAddress)

	wg.Wait()
}
