package pigdns

import (
	"context"
	"errors"
	"net"

	"github.com/miekg/dns"
)

type InternalWriter struct {
	Msg *dns.Msg

	LAddr net.Addr
	RAddr net.Addr
}

func (w *InternalWriter) LocalAddr() net.Addr { return w.LAddr }

func (w *InternalWriter) RemoteAddr() net.Addr { return w.RAddr }

func (w *InternalWriter) WriteMsg(msg *dns.Msg) error {
	w.Msg = msg
	return nil
}

func (w *InternalWriter) Write(b []byte) (int, error) {
	w.Msg = new(dns.Msg)
	err := w.Msg.Unpack(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *InternalWriter) Close() error { return nil }

func (w *InternalWriter) TsigStatus() error { return nil }

func (w *InternalWriter) TsigTimersOnly(ok bool) {}

func (w *InternalWriter) Hijack() {}

func QueryInternal(ctx context.Context, m *dns.Msg, isIPV6 bool) (*dns.Msg, error) {
	if ctx.Value(PigContextKey) == nil {
		return nil, errors.New("no context")
	}
	pc := ctx.Value(PigContextKey).(*PigContext)

	c := context.WithValue(context.Background(), PigContextKey, &PigContext{
		IsDOH:    false,
		Chain:    pc.Chain,
		Internal: true,
	})

	chain := pc.Chain

	rw := &InternalWriter{
		LAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
		RAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
	}
	if isIPV6 {
		rw.LAddr = &net.TCPAddr{IP: net.ParseIP("::1"), Port: 53}
		rw.RAddr = &net.TCPAddr{IP: net.ParseIP("::1"), Port: 53}
	}

	req := &Request{
		ResponseWriter: rw,
		Msg:            m,
	}
	chain.ServeDNS(c, req)

	return rw.Msg, nil
}
