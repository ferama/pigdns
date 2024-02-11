package pigdns

import (
	"context"

	"github.com/miekg/dns"
)

type contextKey string

const PigContextKey contextKey = "pig-context"

type PigContext struct {
	IsDOH    bool
	Rcode    int
	Chain    Handler
	Internal bool
}

func newContext(w dns.ResponseWriter, m *dns.Msg, isDOH bool, chain Handler) context.Context {
	ctx := context.WithValue(context.Background(), PigContextKey, &PigContext{
		IsDOH:    isDOH,
		Chain:    chain,
		Internal: false,
	})

	return ctx
}
