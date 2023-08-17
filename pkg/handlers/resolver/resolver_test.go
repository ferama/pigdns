package resolver

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
)

type fakeRespWriter struct{}

func (f *fakeRespWriter) Close() error { return nil }
func (f *fakeRespWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}
}
func (f *fakeRespWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}
}
func (f *fakeRespWriter) WriteMsg(*dns.Msg) error   { return nil }
func (f *fakeRespWriter) Write([]byte) (int, error) { return 0, nil }
func (f *fakeRespWriter) TsigStatus() error         { return nil }
func (f *fakeRespWriter) TsigTimersOnly(bool)       {}
func (f *fakeRespWriter) Hijack()                   {}

func TestResolveNS(t *testing.T) {
	resolver := &handler{}
	msg := new(dns.Msg)
	msg.SetQuestion("google.it.", dns.TypeA)

	rootNS := fmt.Sprintf("%s:53", getRootNSIPv4())
	resp, err := resolver.queryNS(msg, rootNS)
	if err != nil {
		t.Fatalf(err.Error())
	}

	frw := &fakeRespWriter{}
	r := &pigdns.Request{
		ResponseWriter: frw,
		Msg:            msg,
	}
	ns, err := resolver.resolveNS(context.TODO(), r, resp)
	if err != nil {
		t.Fatalf(err.Error())
	}

	gns := []string{
		"194.0.16.215",   // a.dns.it
		"45.142.220.39",  // d.dns.it
		"193.206.141.46", // r.dns.it
		"217.29.76.4",    // m.dns.it
		"194.119.192.34", // nameserver.cnr.it
		"192.12.192.5",   // dns.nic.it
	}
	found := false
	for _, i := range gns {
		if fmt.Sprintf("%s:53", i) == ns {
			found = true
			break
		}
	}
	t.Logf("answer = %s", ns)
	if !found {
		t.Fatal()
	}
}
