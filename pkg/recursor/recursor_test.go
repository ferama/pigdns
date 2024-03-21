package recursor

import (
	"context"
	"testing"

	"github.com/ferama/pigdns/pkg/metrics"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/racer"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
)

var domainCases = []string{
	"edge-114.defra2.icloud-content.com",
	"authsvc.svcs.teams.office.com",
	"incanto.ru",
	"c0551612.cdn.cloudfiles.rackspacecloud.com",
	"ib.adnxs.com",
	"eu-auth2.samsungosp.com",
	"iam.cloud.ibm.com",
	"js.monitor.azure.com",
	"geo-applefinance-cache.internal.query.g03.yahoodns.net",
	"proxy.safebrowsing.apple",
	"docs.aws.amazon.com",
}

type testHandler struct {
	Next     pigdns.Handler
	recursor *Recursor
}

func (h *testHandler) ServeDNS(c context.Context, r *pigdns.Request) {
	m, err := h.recursor.Query(c, r.Msg, r.FamilyIsIPv6())
	if err != nil {
		// if m != nil {
		// 	r.ReplyWithStatus(m, m.Rcode)
		// 	return
		// }
		r.ReplyWithStatus(r.Msg, dns.RcodeServerFailure)
		return
	}
	if len(m.Answer) != 0 || len(m.Ns) != 0 {
		m.RecursionAvailable = true
		m.Authoritative = false
		utils.MsgSetupEdns(m)

		// set the do flag
		if r.IsDo() {
			utils.MsgSetDo(m, true)
		}

		r.ReplyWithStatus(m, m.Rcode)
		return
	}
	// h.Next.ServeDNS(c, r)
	r.ReplyWithStatus(m, dns.RcodeServerFailure)
}

func testCtx(r *Recursor) context.Context {
	metrics.Reset()
	handler := &testHandler{
		recursor: r,
	}

	return context.WithValue(context.Background(), pigdns.PigContextKey, &pigdns.PigContext{
		Chain: handler,
	})
}

func TestDomainCases(t *testing.T) {
	qr := racer.NewCachedQueryRacer(t.TempDir(), 1024*100)
	recursor := New(t.TempDir(), 1024*100, qr)

	for _, domain := range domainCases {
		fqdn := dns.Fqdn(domain)
		req := new(dns.Msg)
		req.SetQuestion(fqdn, dns.TypeA)
		ans, err := recursor.Query(testCtx(recursor), req, false)
		if err != nil {
			t.Fail()
			return
		}
		if ans.Rcode != dns.RcodeSuccess {
			t.Fatalf("test failed: %s", domain)
		}

		rr := utils.MsgExtractByType(ans, dns.TypeA, "")
		if len(rr) == 0 {
			t.Fatalf("test failed no records: %s", domain)
		}
	}
}

func TestQuery(t *testing.T) {
	qr := racer.NewCachedQueryRacer(t.TempDir(), 1024*100)
	recursor := New(t.TempDir(), 1024*100, qr)

	fqdn := dns.Fqdn("example.com")
	req := new(dns.Msg)
	req.SetQuestion(fqdn, dns.TypeA)
	ans, err := recursor.Query(testCtx(recursor), req, false)
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
	qr := racer.NewCachedQueryRacer(t.TempDir(), 1024*100)
	recursor := New(t.TempDir(), 1024*100, qr)

	domains := []string{
		"dnssec-failed.org",
		"rhybar.cz",
		// "brokendnssec.net", # fixme
	}

	for _, domain := range domains {
		fqdn := dns.Fqdn(domain)
		req := new(dns.Msg)
		req.SetQuestion(fqdn, dns.TypeA)
		ans, err := recursor.Query(testCtx(recursor), req, false)
		if err != nil {
			t.Fatalf("bad dnssec check '%s' %s", domain, err)
		}
		if ans.Rcode != dns.RcodeServerFailure {
			t.Fatalf("bad dnssec check '%s' failure expected", domain)
		}
	}
}

func TestGoodDNSSEC(t *testing.T) {
	qr := racer.NewCachedQueryRacer(t.TempDir(), 1024*100)
	recursor := New(t.TempDir(), 1024*100, qr)

	domains := []string{
		"internetsociety.org",
		"dnssec-tools.org",
	}

	for _, domain := range domains {
		fqdn := dns.Fqdn(domain)
		req := new(dns.Msg)
		req.SetQuestion(fqdn, dns.TypeA)
		ans, err := recursor.Query(testCtx(recursor), req, false)
		if err != nil {
			t.Fatalf("good dnssec check '%s' %s", domain, err)
		}
		if ans.Rcode == dns.RcodeServerFailure {
			t.Fatalf("good dnssec check '%s' failure expected", domain)
		}
	}
}
