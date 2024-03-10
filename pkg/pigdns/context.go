package pigdns

import (
	"context"
)

type contextKey string

const PigContextKey contextKey = "pig-context"

type PigContext struct {
	IsDOH    bool
	Rcode    int
	Chain    Handler
	Internal bool
}

func newContext(isDOH bool, chain Handler) context.Context {
	ctx := context.WithValue(context.Background(), PigContextKey, &PigContext{
		IsDOH:    isDOH,
		Chain:    chain,
		Internal: false,
	})

	return ctx
}
