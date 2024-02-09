package racer

import (
	"fmt"

	"github.com/ferama/pigdns/pkg/pigdns"
)

type NS struct {
	Addr    string
	Fqdn    string
	Version pigdns.RequestFamily
}

func (n *NS) Copy() NS {
	c := NS{
		Addr:    n.Addr,
		Fqdn:    n.Fqdn,
		Version: n.Version,
	}
	return c
}

func (n *NS) String() string {
	return n.Addr
}

func (n *NS) withPort() string {
	if n.Version == pigdns.FamilyIPv4 {
		return fmt.Sprintf("%s:53", n.Addr)
	}
	return fmt.Sprintf("[%s]:53", n.Addr)
}
