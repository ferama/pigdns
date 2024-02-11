package cache

import (
	"context"
	"fmt"
	"net"
	"path/filepath"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/metrics"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/utils"
)

const (
	// for logging
	handlerName = "cache"
)

type handler struct {
	Next pigdns.Handler

	ansCache *ansCache
}

func NewCacheHandler(next pigdns.Handler, name string, cacheSize int, datadir string) *handler {

	h := &handler{
		Next:     next,
		ansCache: newAnsCache(filepath.Join(datadir, "cache", name), name, cacheSize),
	}

	metrics.Instance().RegisterCache(name)
	metrics.Instance().GetCacheCapacityMetric(name).Set(float64(cacheSize))

	return h

}

func (h *handler) ServeDNS(c context.Context, r *pigdns.Request) {

	q := r.Msg.Question[0]
	reqKey := fmt.Sprintf("%s_%d_%d", q.Name, q.Qtype, q.Qclass)

	m, cacheErr := h.ansCache.Get(reqKey)
	if cacheErr == nil {
		cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
		cc.AnweredBy = handlerName
		m.Authoritative = false
		utils.MsgSetupEdns(m)

		// set the do flag
		if r.IsDo() {
			utils.MsgSetDo(m, true)
		}

		r.ReplyWithStatus(m, m.Rcode)
		return
	} else {
		rw := &pigdns.InternalWriter{
			LAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
			RAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
		}
		if r.FamilyIsIPv6() {
			rw.LAddr = &net.TCPAddr{IP: net.ParseIP("::1"), Port: 53}
			rw.RAddr = &net.TCPAddr{IP: net.ParseIP("::1"), Port: 53}
		}

		req := &pigdns.Request{
			ResponseWriter: rw,
			Msg:            r.Msg,
		}

		h.Next.ServeDNS(c, req)

		m = rw.Msg
		h.ansCache.Set(reqKey, m)

		r.ReplyWithStatus(m, m.Rcode)
	}
}
