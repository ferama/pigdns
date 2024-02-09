package recursor

import (
	"fmt"
	"sync"

	"github.com/ferama/pigdns/pkg/racer"
)

type authServers struct {
	sync.RWMutex

	Zone string

	List []racer.NS
	TTL  uint32
}

func (a *authServers) SetTTL(ttl uint32) {
	if a.TTL == 0 {
		a.TTL = ttl
	} else {
		a.TTL = min(a.TTL, ttl)
	}
}

func (a *authServers) String() string {
	ret := fmt.Sprintf("\n=== ZONE: %s ===", a.Zone)
	for _, i := range a.List {
		ret = fmt.Sprintf("%s\nfqdn: %s, ip: %s", ret, i.Fqdn, i.Addr)
	}
	return ret
}
