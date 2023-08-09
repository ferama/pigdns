package regexip

import (
	"context"
	"log"
	"net"
	"testing"
	"time"

	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
)

const testListenAddress = "127.0.0.1:6354"

func startServer() *dns.Server {
	n := pigdns.HandlerFunc(func(c context.Context, w dns.ResponseWriter, m *dns.Msg) {})
	rxip := &Handler{
		Next: n,
	}
	pigdns.Handle("pig.io.", rxip)

	server := &dns.Server{
		Addr: testListenAddress,
		Net:  "udp",
	}
	go func() {
		log.Printf("listening on %s", testListenAddress)
		err := server.ListenAndServe()
		if err != nil {
			log.Fatalf("failed to start server: %s\n ", err.Error())
		}
	}()

	return server
}

func TestA(t *testing.T) {
	server := startServer()
	defer server.Shutdown()

	time.Sleep(1 * time.Second)

	testsA := map[string]string{
		"127-0-0-1.pig.io":                "127.0.0.1",
		"prefix-127-0-0-1.pig.io":         "127.0.0.1",
		"127-0-0-1-suffix.pig.io":         "127.0.0.1",
		"prefix-127-0-0-1-suffix.pig.io":  "127.0.0.1",
		"a-b-c-192-168-10-1-a-b-c.pig.io": "192.168.10.1",
	}
	for k, v := range testsA {
		m := new(dns.Msg)
		m.SetQuestion(k+".", dns.TypeA)
		resp, err := dns.Exchange(m, testListenAddress)
		if err != nil {
			t.Fatalf("Expected to receive reply, but didn't: %s", err)
		}
		if len(resp.Answer) != 1 {
			t.Fatal("expeected one answer")
		}
		rr := resp.Answer[0]
		a := rr.(*dns.A)
		ip := net.ParseIP(v)
		if !a.A.Equal(ip) {
			t.Fatalf("expected ip '%s' got '%s'", v, a.A)
		}
	}
}

func TestAAAA(t *testing.T) {
	server := startServer()
	defer server.Shutdown()

	time.Sleep(1 * time.Second)

	testsAAAA := map[string]string{
		"2001-0db8--1428-57ab.pig.io":               "2001:0db8::1428:57ab",
		"prefix-2001-0db8--1428-57ab.pig.io":        "2001:0db8::1428:57ab",
		"2001-0db8--1428-57ab-suffix.pig.io":        "2001:0db8::1428:57ab",
		"prefix-2001-0db8--1428-57ab-suffix.pig.io": "2001:0db8::1428:57ab",
	}
	for k, v := range testsAAAA {
		m := new(dns.Msg)
		m.SetQuestion(k+".", dns.TypeAAAA)
		resp, err := dns.Exchange(m, testListenAddress)
		if err != nil {
			t.Fatalf("Expected to receive reply, but didn't: %s", err)
		}
		if len(resp.Answer) != 1 {
			t.Fatal("expeected one answer")
		}
		rr := resp.Answer[0]
		aaaa := rr.(*dns.AAAA)
		ip := net.ParseIP(v)
		if !aaaa.AAAA.Equal(ip) {
			t.Fatalf("expected ip '%s' got '%s'", v, aaaa.AAAA)
		}
	}
}
