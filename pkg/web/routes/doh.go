package routes

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"

	"github.com/ferama/pigdns/pkg/doh"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
)

func DohHandler() gin.HandlerFunc {

	dnsHandler := pigdns.HandlerFunc(func(ctx context.Context, r *pigdns.Request) {
		dns.DefaultServeMux.ServeDNS(r.ResponseWriter, r.Msg)
	})

	return func(c *gin.Context) {
		r := c.Request

		msg, err := doh.RequestToMsg(r)
		if err != nil {
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		h, p, _ := net.SplitHostPort(r.RemoteAddr)
		port, _ := strconv.Atoi(p)
		dw := &doh.DoHWriter{
			// Laddr: s.listenAddr,
			Raddr: &net.TCPAddr{IP: net.ParseIP(h), Port: port},
			Req:   r,
		}

		// We just call the normal chain handler - all error handling is done there.
		// We should expect a packet to be returned that we can send to the client.
		req := &pigdns.Request{
			Msg:            msg,
			ResponseWriter: dw,
		}
		dnsHandler.ServeDNS(context.Background(), req)

		// See section 4.2.1 of RFC 8484.
		// We are using code 500 to indicate an unexpected situation when the chain
		// handler has not provided any response message.
		if dw.Msg == nil {
			c.AbortWithError(http.StatusInternalServerError, errors.New("no response"))
			return
		}

		buf, _ := dw.Msg.Pack()
		c.Header("Content-Type", doh.MimeType)
		// w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%f", age.Seconds()))
		c.Header("Content-Length", strconv.Itoa(len(buf)))
		c.Writer.WriteHeader(http.StatusOK)
		c.Writer.Write(buf)
	}
}
