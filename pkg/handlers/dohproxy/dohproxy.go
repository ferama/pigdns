package dohproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/ferama/pigdns/pkg/doh"
	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/rs/zerolog/log"
)

const (
	handlerName = "doh-proxy"
)

type handler struct {
	serverURI  string
	serverAddr string

	Next pigdns.Handler
}

// NewDohProxy creates a doh proxy Handler.
// The serverURI parameter is the DNS name of the doh server (without https or port)
// The serverAddr is the resolved ip address of the doh server
func NewDohProxy(serverURI string, serverAddr string, next pigdns.Handler) *handler {
	h := &handler{
		serverURI:  serverURI,
		serverAddr: serverAddr,
		Next:       next,
	}
	return h
}

func (h *handler) ServeDNS(c context.Context, r *pigdns.Request) {
	cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
	cc.AnweredBy = handlerName

	serverHTTPAddr := fmt.Sprintf("https://%s", h.serverURI)
	req, err := doh.NewRequest("POST", serverHTTPAddr, r.Msg)
	if err != nil {
		log.Err(err)
		h.Next.ServeDNS(c, r)
		return
	}

	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 5 * time.Second,
	}

	http.DefaultTransport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// force resolve doh server name to its ip
		if addr == fmt.Sprintf("%s:443", h.serverURI) {
			addr = fmt.Sprintf("%s:443", h.serverAddr)
		}
		return dialer.DialContext(ctx, network, addr)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Err(err)
		h.Next.ServeDNS(c, r)
		return
	}
	respMsg, err := doh.ResponseToMsg(res)
	if err != nil {
		log.Err(err)
		h.Next.ServeDNS(c, r)
		return
	}

	utils.MsgSetupEdns(respMsg)

	r.Reply(respMsg)
	h.Next.ServeDNS(c, r)
}
