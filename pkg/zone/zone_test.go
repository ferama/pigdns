package zone

import (
	"log"
	"os"
	"path"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testListenAddress = "127.0.0.1:6353"

func createTempFile(t *testing.T, content string) string {
	tmpfile := path.Join(t.TempDir(), "zone.conf")
	err := os.WriteFile(tmpfile, []byte(content), 0644)
	if err != nil {
		t.Fail()
	}

	return tmpfile
}

func startServer(zoneFile string) *dns.Server {
	n := dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {})
	zone := New(n, "pig.io", zoneFile)
	dns.Handle("pig.io.", zone)

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
	time.Sleep(1 * time.Second)

	server := startServer(zoneFile)
	defer server.Shutdown()

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