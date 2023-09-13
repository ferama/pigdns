package recursor

import "github.com/ferama/pigdns/pkg/pigdns"

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

	rootNSIPv6 = []string{
		"2001:503:ba3e::2:30", //a
		"2001:500:200::b",     //b
		"2001:500:2::c",       //c
		"2001:500:2d::d",      //d
		"2001:500:a8::e",      //e
		"2001:500:2f::f",      //f
		"2001:500:12::d0d",    //g
		"2001:500:1::53",      //h
		"2001:7fe::53",        //i
		"2001:503:c27::2:30",  //j
		"2001:7fd::1",         //k
		"2001:500:9f::42",     //l
		"2001:dc3::35",        //m
	}
)

func getRootServers() *authServers {
	severs := &authServers{}
	for _, s := range rootNSIPv4 {
		as := &nsServer{
			Addr:    s,
			Version: pigdns.FamilyIPv4,
		}
		severs.List = append(severs.List, as)
	}

	for _, s := range rootNSIPv6 {
		as := &nsServer{
			Addr:    s,
			Version: pigdns.FamilyIPv6,
		}
		severs.List = append(severs.List, as)
	}

	return severs
}
