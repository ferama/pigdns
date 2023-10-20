package recursor

import "github.com/ferama/pigdns/pkg/pigdns"

var (
	// a.root-servers.net.
	// b.root-servers.net.
	// ...

	rootNS = []struct {
		IPV4 string
		IPV6 string
		Fqdn string
	}{
		{
			IPV4: "198.41.0.4",
			IPV6: "2001:503:ba3e::2:30",
			Fqdn: "a.root-servers.net",
		},
		{
			IPV4: "199.9.14.201",
			IPV6: "2001:500:200::b",
			Fqdn: "b.root-servers.net",
		},
		{
			IPV4: "192.33.4.12",
			IPV6: "2001:500:2::c",
			Fqdn: "c.root-servers.net",
		},
		{
			IPV4: "199.7.91.13",
			IPV6: "2001:500:2d::d",
			Fqdn: "d.root-servers.net",
		},
		{
			IPV4: "192.203.230.10",
			IPV6: "2001:500:a8::e",
			Fqdn: "e.root-servers.net",
		},
		{
			IPV4: "192.5.5.241",
			IPV6: "2001:500:2f::f",
			Fqdn: "f.root-servers.net",
		},
		{
			IPV4: "192.112.36.4",
			IPV6: "2001:500:12::d0d",
			Fqdn: "g.root-servers.net",
		},
		{
			IPV4: "198.97.190.53",
			IPV6: "2001:500:1::53",
			Fqdn: "h.root-servers.net",
		},
		{
			IPV4: "192.36.148.17",
			IPV6: "2001:7fe::53",
			Fqdn: "i.root-servers.net",
		},
		{
			IPV4: "192.58.128.30",
			IPV6: "2001:503:c27::2:30",
			Fqdn: "j.root-servers.net",
		},
		{
			IPV4: "193.0.14.129",
			IPV6: "2001:7fd::1",
			Fqdn: "k.root-servers.net",
		},
		{
			IPV4: "199.7.83.42",
			IPV6: "2001:500:9f::42",
			Fqdn: "l.root-servers.net",
		},
		{
			IPV4: "202.12.27.33",
			IPV6: "2001:dc3::35",
			Fqdn: "m.root-servers.net",
		},
	}

	rootKeys = []string{
		".			172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	}
)

func getRootServers() *authServers {
	servers := &authServers{
		Zone: ".",
	}
	for _, s := range rootNS {
		as := &nsServer{
			Addr:    s.IPV4,
			Fqdn:    s.Fqdn,
			Version: pigdns.FamilyIPv4,
		}
		servers.List = append(servers.List, as)
	}

	for _, s := range rootNS {
		as := &nsServer{
			Addr:    s.IPV6,
			Fqdn:    s.Fqdn,
			Version: pigdns.FamilyIPv6,
		}
		servers.List = append(servers.List, as)
	}

	return servers
}
