package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"

	"github.com/ferama/pigdns/pkg/acmec"
	"github.com/ferama/pigdns/pkg/certman"
	"github.com/ferama/pigdns/pkg/regexip"
	"github.com/miekg/dns"
)

const (
	defaultRes = "pigdns.io. 1800 IN SOA pigdns.io. pigdns.io. 1502165581 14400 3600 604800 14400"
)

// the first handler that write back to the client calling
// w.WriteMsg(m) win. No other handler can write back anymore
// Chain rings are called in reverse order
func buildChain(domain string) dns.Handler {
	var chain dns.Handler

	// leaf handler (is the latest one)
	chain = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		rr, _ := dns.NewRR(defaultRes)
		m.Answer = append(m.Answer, rr)

		w.WriteMsg(m)
	})

	chain = &regexip.Handler{Next: chain}
	chain = &acmec.Handler{Next: chain}

	return chain
}

func main() {
	domain := flag.String("domain", "", "a domain")
	port := flag.Int("port", 53, "listen udp port")
	flag.Parse()

	if *domain == "" {
		log.Fatal("you must set the domain flag")
	}

	cm := certman.New(*domain)
	go cm.Run()

	// attach request handler func
	dns.Handle(fmt.Sprintf("%s.", *domain), buildChain(*domain))

	// start server
	server := &dns.Server{Addr: ":" + strconv.Itoa(*port), Net: "udp"}
	log.Printf("starting at %d\n", *port)

	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("failed to start server: %s\n ", err.Error())
	}
}
