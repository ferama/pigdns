package server

import (
	"context"

	"github.com/ferama/pigdns/pkg/handlers/acmec"
	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/handlers/regexip"
	"github.com/ferama/pigdns/pkg/handlers/resolver"
	"github.com/ferama/pigdns/pkg/handlers/root"
	"github.com/ferama/pigdns/pkg/handlers/zone"
	"github.com/ferama/pigdns/pkg/pigdns"
)

// BuildResolverHandler creates an handler that resolves recursively
// starting from root NS
func BuildResolverHandler(datadir string, allowedNets []string) pigdns.Handler {
	var chain pigdns.Handler

	chain = pigdns.HandlerFunc(func(ctx context.Context, r *pigdns.Request) {
		r.ResponseWriter.Close()
		if ctx.Value(collector.CollectorContextKey) != nil {
			cc := ctx.Value(collector.CollectorContextKey).(*collector.CollectorContext)
			cc.AnweredBy = "failure"
		}
	})
	chain = resolver.NewResolver(chain, datadir, allowedNets)
	chain = &collector.Handler{Next: chain}

	return chain
}

// BuildDomainHandler craetes an handler that resolves custom zone
func BuildDomainHandler(zoneFilePath string, domain string, certmanEnable bool) pigdns.Handler {
	// the first handler that write back to the client calling
	// w.WriteMsg(m) win. No other handler can write back anymore
	// Chain rings are called in reverse order
	var chain pigdns.Handler

	// leaf handler (is the latest one)
	chain = &root.Handler{
		Domain:   domain,
		ZoneFile: zoneFilePath,
	}

	chain = &regexip.Handler{Next: chain}
	if zoneFilePath != "" {
		chain = zone.New(chain, domain, zoneFilePath)
	}
	if certmanEnable {
		chain = &acmec.Handler{Next: chain}
	}

	chain = &collector.Handler{Next: chain}
	return chain
}
