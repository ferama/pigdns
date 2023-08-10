package pigdns

import (
	"context"

	"github.com/miekg/dns"
)

type Handler interface {
	ServeDNS(c context.Context, r *Request)
}

type HandlerFunc func(context.Context, *Request)

// ServeDNS calls f(w, r).
func (f HandlerFunc) ServeDNS(c context.Context, r *Request) {
	f(c, r)
}

func Handle(pattern string, handler Handler) {
	dns.HandleFunc(pattern, func(w dns.ResponseWriter, m *dns.Msg) {
		ctx := newContext(w, m)
		req := &Request{
			ResponseWriter: w,
			Msg:            m,
		}
		handler.ServeDNS(ctx, req)
	})
}
