package blocklist

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
)

const (
	handlerName = "blocklist"
)

var (
	commentsRE = regexp.MustCompile(`^\s*#`)
)

type handler struct {
	Next pigdns.Handler

	lists map[string]map[string]bool
}

func NewBlocklistHandler(uri []string, next pigdns.Handler) *handler {
	h := &handler{
		Next: next,

		lists: map[string]map[string]bool{},
	}

	for _, u := range uri {
		lowered := strings.ToLower(u)
		if strings.HasPrefix(lowered, "http") {
			res, err := http.Get(u)
			if err != nil {
				log.Warn().Msgf("cannot load blocklist: %s", u)
				continue
			}
			b, err := io.ReadAll(res.Body)
			if err != nil {
				log.Warn().Msgf("cannot load blocklist: %s. Err: %s", u, err)
				continue
			}
			content := string(b)
			lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")

			h.lists[u] = make(map[string]bool)
			for _, l := range lines {
				if !commentsRE.Match([]byte(l)) {
					key := strings.ToLower(l)
					h.lists[u][dns.Fqdn(key)] = true
				}
			}
		}
	}

	return h
}

func (h *handler) ServeDNS(c context.Context, r *pigdns.Request) {
	allowed := true

	key := strings.ToLower(r.Name())

	for _, blocklist := range h.lists {
		if _, ok := blocklist[key]; ok {
			allowed = false
		}
	}

	if !allowed {
		log.Printf("[blocklist handler] domain '%s' is not allowed", r.Name())
		if c.Value(collector.CollectorContextKey) != nil {
			cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
			cc.AnweredBy = handlerName
		}
		m := new(dns.Msg)
		r.ReplyWithStatus(m, dns.RcodeRefused)
		return
	}
	h.Next.ServeDNS(c, r)
}
