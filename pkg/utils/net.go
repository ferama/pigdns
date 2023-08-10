package utils

import (
	"net"
	"net/netip"
)

// IsAddrInNetwork checks if an address is contained into any of the
// networks defined in denyNet
// Example:
// allowedNets := []string{"172.17.0.0/16"}
// addr := "172.17.0.2"
// returns true
func IsAddrInNetwork(addr string, networks []string) (bool, error) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		ipadd, err := netip.ParseAddrPort(addr)
		if err != nil {
			return false, err
		}
		ip = ipadd.Addr()
	}

	for _, n := range networks {
		network, err := netip.ParsePrefix(n)
		if err != nil {
			return false, err
		}
		if network.Contains(ip) {
			return true, nil
		}
	}

	return false, nil
}

func IsClientAllowed(client net.Addr, allowedNets []string) (bool, error) {
	if len(allowedNets) == 0 {
		return true, nil
	}
	r, err := IsAddrInNetwork(client.String(), allowedNets)
	if err != nil {
		return false, err
	}
	return r, nil
}
