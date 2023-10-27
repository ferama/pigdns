package pigdns

import (
	"context"

	"github.com/miekg/dns"
)

type contextKey string

const PigContextKey contextKey = "pig-context"

type PigContext struct {
	IsDOH     bool
	CacheHits int
	CacheMiss int
	Rcode     int
}

func newContext(w dns.ResponseWriter, m *dns.Msg, isDOH bool) context.Context {
	ctx := context.WithValue(context.Background(), PigContextKey, &PigContext{
		IsDOH:     isDOH,
		CacheHits: 0,
		CacheMiss: 0,
	})

	return ctx
}
