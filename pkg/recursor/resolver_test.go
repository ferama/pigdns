package recursor

import (
	"context"
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

func TestResolveNS(t *testing.T) {
	resolver := &Recursor{}
	msg := new(dns.Msg)
	msg.SetQuestion("google.it.", dns.TypeA)

	rootNS := fmt.Sprintf("%s:53", getRootNSIPv4())
	resp, err := resolver.queryNS(msg, rootNS)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ns, err := resolver.resolveNS(context.TODO(), msg, resp, false)
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
