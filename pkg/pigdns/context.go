package pigdns

import (
	"context"

	"github.com/miekg/dns"
)

type PigContext context.Context

func newContext(w dns.ResponseWriter, m *dns.Msg) PigContext {
	ctx := context.Background()

	return ctx
}