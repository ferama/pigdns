package zone

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

func GetSOArecord(domain string, zoneFile string) dns.RR {
	currentTime := time.Now().Format("20060102")

	// fallback to domain (not correct but we could not have a better answer)
	ns := domain

	// if we have a nameserver defined in our zone file, use it as the right
	// answer
	nameservers := ZoneFileInst(zoneFile, domain).GetNS()
	if len(nameservers) > 0 {
		ns = nameservers[0].Ns
	}

	soa := fmt.Sprintf("%s. 300 IN SOA %s %s %s01 14400 3600 14400 60", domain, ns, domain, currentTime)
	rr, _ := dns.NewRR(soa)
	return rr
}
