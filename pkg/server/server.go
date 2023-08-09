package server

import (
	"log"
	"strconv"
	"sync"

	"github.com/miekg/dns"
)

type Server struct {
	port int
}

func NewServer(port int) *Server {
	s := &Server{
		port: port,
	}
	return s
}

func (s *Server) run(net string) {
	server := &dns.Server{
		Addr: ":" + strconv.Itoa(s.port),
		Net:  net,
	}
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("failed to start server: %s\n ", err.Error())
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

	log.Printf("listening on ':%d'", s.port)

	wg.Wait()
}
