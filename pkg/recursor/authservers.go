package recursor

import (
	"fmt"
)

// Version type
type Version byte

const (
	// IPv4 mode
	IPv4 Version = 0x1

	// IPv6 mode
	IPv6 Version = 0x2
)

type nsServer struct {
	Addr    string
	Version Version
	TTL     uint32
}

func (n *nsServer) String() string {
	return n.Addr
}

func (n *nsServer) withPort() string {
	if n.Version == IPv4 {
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
