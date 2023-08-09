package pigdns

import (
	"context"

	"github.com/miekg/dns"
)

type Handler interface {
	ServeDNS(c context.Context, w dns.ResponseWriter, r *dns.Msg)
}

type HandlerFunc func(context.Context, dns.ResponseWriter, *dns.Msg)

// ServeDNS calls f(w, r).
func (f HandlerFunc) ServeDNS(c context.Context, w dns.ResponseWriter, r *dns.Msg) {
	f(c, w, r)
}

func Handle(pattern string, handler Handler) {
	dns.HandleFunc(pattern, func(w dns.ResponseWriter, m *dns.Msg) {
		ctx := InitializeCtx(w, m)
		handler.ServeDNS(ctx, w, m)
	})
}
