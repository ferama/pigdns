package resolver

import (
	"math/rand"
)

var (
	// a.root-servers.net.
	// b.root-servers.net.
	// ...
	rootNSIPv4 = []string{
		"198.41.0.4",     //a
		"199.9.14.201",   //b
		"192.33.4.12",    //c
		"199.7.91.13",    //d
		"192.203.230.10", //e
		"192.5.5.241",    //f
		"192.112.36.4",   //g
		"198.97.190.53",  //h
		"192.36.148.17",  //i
		"192.58.128.30",  //j
		"193.0.14.129",   //k
		"199.7.83.42",    //l
		"202.12.27.33",   //m
	}

	rootNSIPv6 = []string{}
)

func getRootNS() string {
	n := rand.Intn(len(rootNSIPv4))
	return rootNSIPv4[n]
}
