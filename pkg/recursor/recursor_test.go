package recursor

import (
	"context"
	"testing"

	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
)

func TestQuery(t *testing.T) {

	recursor := New(t.TempDir(), 1024*100)

	fqdn := dns.Fqdn("example.com")
	req := new(dns.Msg)
	req.SetQuestion(fqdn, dns.TypeA)
	ans, err := recursor.Query(context.TODO(), req, false)
	if err != nil {
		t.Fail()
	}

	rr := utils.MsgExtractByType(ans, dns.TypeA, fqdn)
	if len(rr) == 0 {
		t.Fail()
	}
}

// https://www.internetsociety.org/resources/deploy360/2013/dnssec-test-sites/
func TestBadDNSSEC(t *testing.T) {
	recursor := New(t.TempDir(), 1024*100)

	sites := []string{
		"dnssec-failed.org",
		"rhybar.cz",
	}

	for _, site := range sites {
		fqdn := dns.Fqdn(site)
		req := new(dns.Msg)
		req.SetQuestion(fqdn, dns.TypeA)
		ans, err := recursor.Query(context.TODO(), req, false)
		if err != nil {
			t.Fail()
		}
		if ans.Rcode != dns.RcodeServerFailure {
			t.Fail()
		}
	}
}

func TestGoodDNSSEC(t *testing.T) {
	recursor := New(t.TempDir(), 1024*100)

	sites := []string{
		"internetsociety.org",
		"dnssec-tools.org",
	}

	for _, site := range sites {
		fqdn := dns.Fqdn(site)
		req := new(dns.Msg)
		req.SetQuestion(fqdn, dns.TypeA)
		ans, err := recursor.Query(context.TODO(), req, false)
		if err != nil {
			t.Fail()
		}
		if ans.Rcode == dns.RcodeServerFailure {
			t.Fail()
		}
	}
}
