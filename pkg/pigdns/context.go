package pigdns

import (
	"context"

	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
)

type (
	IsIPv6 struct{}
)

type PigContext context.Context

func newContext(w dns.ResponseWriter, m *dns.Msg) PigContext {
	ipv6 := utils.IsIPv6(w.RemoteAddr())
	ctx := context.WithValue(context.Background(), IsIPv6{}, ipv6)

	return ctx
}
