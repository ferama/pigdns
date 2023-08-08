package utils

import (
	"net"
	"net/netip"
	"strings"
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

func IsIPv6(remote net.Addr) bool {
	var ip string
	switch addr := remote.(type) {
	case *net.UDPAddr:
		ip = addr.IP.String()
	case *net.TCPAddr:
		ip = addr.IP.String()
	}
	if ip == "" {
		return false
	}
	if strings.Count(ip, ":") >= 2 {
		return true
	}
	return false
}
func IsIPv4(remote net.Addr) bool {
	var ip string
	switch addr := remote.(type) {
	case *net.UDPAddr:
		ip = addr.IP.String()
	case *net.TCPAddr:
		ip = addr.IP.String()
	}
	if ip == "" {
		return false
	}

	if strings.Count(ip, ":") >= 2 {
		return false
	}
	return true
}
