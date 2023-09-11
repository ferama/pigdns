package recursor

import (
	"fmt"

	"github.com/ferama/pigdns/pkg/pigdns"
)

type nsServer struct {
	Addr    string
	Version pigdns.RequestFamily
	TTL     uint32
}

func (n *nsServer) String() string {
	return n.Addr
}

func (n *nsServer) withPort() string {
	if n.Version == pigdns.FamilyIPv4 {
		return fmt.Sprintf("%s:53", n.Addr)
	}
	return fmt.Sprintf("[%s]:53", n.Addr)
}

type authServers struct {
	Zone string

	List []nsServer
}

func (a *authServers) String() string {
	ret := fmt.Sprintf("\n=== ZONE: %s ===", a.Zone)
	for _, i := range a.List {
		ret = fmt.Sprintf("%s\n%s", ret, i.Addr)
	}
	return ret
}
