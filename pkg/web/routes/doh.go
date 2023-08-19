package routes

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/ferama/pigdns/pkg/doh"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/utils"
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

		// build the request object and call the chain handler
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

		minTTL := utils.MsgGetMinTTL(dw.Msg)

		buf, _ := dw.Msg.Pack()
		c.Header("Content-Type", doh.MimeType)
		c.Header("Cache-Control", fmt.Sprintf("max-age=%d", minTTL))
		c.Header("Content-Length", strconv.Itoa(len(buf)))
		c.Writer.WriteHeader(http.StatusOK)
		c.Writer.Write(buf)
	}
}
