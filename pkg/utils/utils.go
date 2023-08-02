package utils

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func GetSOArecord() dns.RR {
	domain := viper.GetString("domain")
	currentTime := time.Now().Format("20060102")
	// TODO: get the correct NS if we have a zone file
	ns := domain
	soa := fmt.Sprintf("%s. 300 IN SOA %s %s %s01 14400 3600 14400 60", domain, ns, ns, currentTime)
	rr, _ := dns.NewRR(soa)
	return rr
}
