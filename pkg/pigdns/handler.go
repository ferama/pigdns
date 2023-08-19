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

// Handle registers and handler using the dns.DefaultMux
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

// HandleMux registers an handler using a custom Mux
func HandleMux(pattern string, handler Handler, mux *dns.ServeMux) {
	mux.HandleFunc(pattern, func(w dns.ResponseWriter, m *dns.Msg) {
		ctx := newContext(w, m)
		req := &Request{
			ResponseWriter: w,
			Msg:            m,
		}
		handler.ServeDNS(ctx, req)
	})
}
