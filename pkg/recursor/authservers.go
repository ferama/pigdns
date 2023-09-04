package recursor

import (
	"errors"
	"fmt"
	"math/rand"
)

// Version type
type Version byte

const (
	// IPv4 mode
	IPv4 Version = 0x1

	// IPv6 mode
	IPv6 Version = 0x2
)

type NSServer struct {
	Addr    string
	Version Version
}

func (n *NSServer) withPort() string {
	if n.Version == IPv4 {
		return fmt.Sprintf("%s:53", n.Addr)
	}
	return fmt.Sprintf("[%s]:53", n.Addr)
}

type authServers struct {
	Zone string

	List []NSServer
}

func (a *authServers) String() string {
	ret := fmt.Sprintf("\n=== ZONE: %s ===", a.Zone)
	for _, i := range a.List {
		ret = fmt.Sprintf("%s\n%s", ret, i.Addr)
	}
	return ret
}

func (a *authServers) peekOne(allowIPv6 bool) (*NSServer, error) {
	if len(a.List) == 0 {
		return nil, errors.New("no NS to peek")
	}
	for {
		n := rand.Intn(len(a.List))
		s := a.List[n]
		if !allowIPv6 && s.Version == IPv6 {
			continue
		}
		return &s, nil
	}
}
