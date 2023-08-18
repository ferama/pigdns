package doh

import (
	"net"
	"net/http"

	"github.com/miekg/dns"
)

// DoHWriter is a dns.ResponseWriter that adds more specific LocalAddr and RemoteAddr methods.
type DoHWriter struct {
	// Raddr is the remote's address. This can be optionally set.
	Raddr net.Addr
	// Laddr is our address. This can be optionally set.
	Laddr net.Addr

	// Req is the HTTP Req we're currently handling.
	Req *http.Request

	// Msg is a response to be written to the client.
	Msg *dns.Msg
}

// WriteMsg stores the message to be written to the client.
func (d *DoHWriter) WriteMsg(m *dns.Msg) error {
	d.Msg = m
	return nil
}

// Write stores the message to be written to the client.
func (d *DoHWriter) Write(b []byte) (int, error) {
	d.Msg = new(dns.Msg)
	return len(b), d.Msg.Unpack(b)
}

// RemoteAddr returns the remote address.
func (d *DoHWriter) RemoteAddr() net.Addr {
	return d.Raddr
}

// LocalAddr returns the local address.
func (d *DoHWriter) LocalAddr() net.Addr {
	return d.Laddr
}

// Request returns the HTTP request.
func (d *DoHWriter) Request() *http.Request {
	return d.Req
}

// Close no-op implementation.
func (d *DoHWriter) Close() error {
	return nil
}

// TsigStatus no-op implementation.
func (d *DoHWriter) TsigStatus() error {
	return nil
}

// TsigTimersOnly no-op implementation.
func (d *DoHWriter) TsigTimersOnly(_ bool) {}

// Hijack no-op implementation.
func (d *DoHWriter) Hijack() {}
