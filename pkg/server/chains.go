package server

import (
	"context"

	"github.com/ferama/pigdns/pkg/handlers/acl"
	"github.com/ferama/pigdns/pkg/handlers/acmec"
	"github.com/ferama/pigdns/pkg/handlers/any"
	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/handlers/dohproxy"
	"github.com/ferama/pigdns/pkg/handlers/recursor"
	"github.com/ferama/pigdns/pkg/handlers/regexip"
	"github.com/ferama/pigdns/pkg/handlers/root"
	"github.com/ferama/pigdns/pkg/handlers/zone"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
)

func BuildDOHProxyHandler(serverURI string, serverAddr string) pigdns.Handler {
	var chain pigdns.Handler

	chain = pigdns.HandlerFunc(func(ctx context.Context, r *pigdns.Request) {})
	chain = dohproxy.NewDohProxy(serverURI, serverAddr, chain)
	chain = &collector.Handler{Next: chain}
	return chain
}

// BuildRecursorHandler creates an handler that resolves recursively
// starting from root NS
func BuildRecursorHandler(datadir string, allowedNets []string) pigdns.Handler {
	var chain pigdns.Handler

	chain = pigdns.HandlerFunc(func(ctx context.Context, r *pigdns.Request) {
		// I cannot close the connection here but I need to give an answer
		// anyway. Closing the connections prevents DOH to work properly from
		// browser
		// r.ResponseWriter.Close()

		m := new(dns.Msg)
		m.Authoritative = false
		if ctx.Value(collector.CollectorContextKey) != nil {
			cc := ctx.Value(collector.CollectorContextKey).(*collector.CollectorContext)
			cc.AnweredBy = "failure"
		}
		r.ReplyWithStatus(m, dns.RcodeServerFailure)
	})
	chain = recursor.NewRecursorHandler(chain, datadir)
	// blocks TypeANY requests
	chain = &any.Handler{Next: chain}
	chain = &acl.Handler{Next: chain, AllowedNets: allowedNets}
	chain = &collector.Handler{Next: chain}

	return chain
}

// BuildZoneHandler craetes an handler that resolves custom zone
func BuildZoneHandler(zoneFilePath string, zoneName string, regexipEnable bool, certmanEnable bool) pigdns.Handler {
	// the first handler that write back to the client calling
	// w.WriteMsg(m) win. No other handler can write back anymore
	// Chain rings are called in reverse order
	var chain pigdns.Handler

	// leaf handler (is the latest one)
	chain = &root.Handler{
		Domain:   zoneName,
		ZoneFile: zoneFilePath,
	}

	if regexipEnable {
		chain = &regexip.Handler{Next: chain}
	}
	if zoneFilePath != "" {
		chain = zone.New(chain, zoneName, zoneFilePath)
	}
	if certmanEnable {
		chain = &acmec.Handler{Next: chain}
	}

	chain = &collector.Handler{Next: chain}
	return chain
}
