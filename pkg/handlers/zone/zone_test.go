package zone

import (
	"context"
	"log"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

const testListenAddress = "127.0.0.1:6353"

func createTempFile(t *testing.T, content string) string {
	tmpfile := path.Join(t.TempDir(), "zone.conf")
	err := os.WriteFile(tmpfile, []byte(content), 0644)
	if err != nil {
		t.Fail()
	}
	viper.Set("domain", "pig.io")
	viper.Set("zone-file", tmpfile)

	return tmpfile
}

func startServer(zoneFile string) *dns.Server {
	n := pigdns.HandlerFunc(func(c context.Context, w dns.ResponseWriter, m *dns.Msg) {})
	zone := New(n)
	pigdns.Handle("pig.io.", zone)

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

func TestNS(t *testing.T) {
	z := `
$TTL    30M
			IN  NS      pigdns.io.
	  		IN  A       192.168.200.200
a		   	IN  A       192.168.200.201
a		   	IN  A       192.168.200.202
	`
	zoneFile := createTempFile(t, z)

	t.Log(zoneFile)
	cont, _ := os.ReadFile(zoneFile)
	t.Log(string(cont))

	server := startServer(zoneFile)
	defer server.Shutdown()

	ZoneFileInst().setZoneFile(zoneFile)

	time.Sleep(1 * time.Second)

	m := new(dns.Msg)
	m.SetQuestion("a.pig.io.", dns.TypeA)
	resp, err := dns.Exchange(m, testListenAddress)
	if err != nil {
		t.Fatalf("Expected to receive reply, but didn't: %s", err)
	}
	if len(resp.Answer) != 2 {
		t.Fatalf("Expected two RR in answer section got %d", len(resp.Answer))
	}

	m = new(dns.Msg)
	m.SetQuestion("pig.io.", dns.TypeA)
	resp, err = dns.Exchange(m, testListenAddress)
	if err != nil {
		t.Fatalf("Expected to receive reply, but didn't: %s", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("Expected two RR in answer section got %d", len(resp.Answer))
	}

	m = new(dns.Msg)
	m.SetQuestion("pig.io.", dns.TypeNS)
	resp, err = dns.Exchange(m, testListenAddress)
	if err != nil {
		t.Fatalf("Expected to receive reply, but didn't: %s", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("Expected two RR in answer section got %d", len(resp.Answer))
	}
}

func TestCNAMEA(t *testing.T) {
	z := `
$TTL    30M
			IN  NS      pigdns.io.
a		   	IN  A       192.168.200.201
b		   	IN  CNAME   a
c		   	IN  CNAME   b
d			IN 	AAAA	2a01:4f8:c17:b8f::2
e			IN 	CNAME 	d
`
	zoneFile := createTempFile(t, z)

	server := startServer(zoneFile)
	defer server.Shutdown()

	ZoneFileInst().setZoneFile(zoneFile)

	time.Sleep(1 * time.Second)

	m := new(dns.Msg)
	m.SetQuestion("c.pig.io.", dns.TypeA)
	resp, err := dns.Exchange(m, testListenAddress)
	if err != nil {
		t.Fatalf("Expected to receive reply, but didn't: %s", err)
	}
	if len(resp.Answer) != 3 {
		t.Fatalf("Expected three RR in answer section got %d", len(resp.Answer))
	}
	rr := resp.Answer[0]
	a := rr.(*dns.A)
	ip := net.ParseIP("192.168.200.201")
	if !a.A.Equal(ip) {
		t.Fatal("expected ip to be equals")
	}
}

func TestCNAMEAAAA(t *testing.T) {
	z := `
$TTL    30M
			IN  NS      pigdns.io.
a		   	IN  A       192.168.200.201
b		   	IN  CNAME   a
c		   	IN  CNAME   b
d			IN 	AAAA	2a01:4f8:c17:b8f::2
e			IN 	CNAME 	d
`
	zoneFile := createTempFile(t, z)

	server := startServer(zoneFile)
	defer server.Shutdown()

	ZoneFileInst().setZoneFile(zoneFile)

	time.Sleep(1 * time.Second)

	m := new(dns.Msg)
	m.SetQuestion("e.pig.io.", dns.TypeAAAA)
	resp, err := dns.Exchange(m, testListenAddress)
	if err != nil {
		t.Fatalf("Expected to receive reply (ipv6), but didn't: %s", err)
	}
	if len(resp.Answer) != 2 {
		t.Fatalf("Expected two RR in answer section got %d", len(resp.Answer))
	}
	rr := resp.Answer[0]
	aaaa := rr.(*dns.AAAA)
	ip := net.ParseIP("2a01:4f8:c17:b8f::2")
	if !aaaa.AAAA.Equal(ip) {
		t.Fatal("expected ip to be equals")
	}
}
