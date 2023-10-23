package blocklist

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"os"
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
	isHTTPRE   = regexp.MustCompile(`^http(s)?:\/\/`)
)

type handler struct {
	Next pigdns.Handler

	list map[string]bool
}

func NewBlocklistHandler(blocklists []string, whitelists []string, next pigdns.Handler) *handler {
	h := &handler{
		Next: next,

		list: map[string]bool{},
	}

	for _, u := range blocklists {
		lowered := strings.ToLower(u)
		if isHTTPRE.Match([]byte(lowered)) {
			h.addHTTP(u)
		} else {
			h.addFile(u)
		}
	}

	for _, u := range whitelists {
		h.removeFile(u)
	}

	return h
}

func (h *handler) removeFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Warn().Msgf("[blocklist] '%s'", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		line := scanner.Text()
		delete(h.list, dns.Fqdn(line))
	}
	log.Info().Msgf("[blocklist] '%s' loaded as whitelist", path)
}

func (h *handler) addFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Warn().Msgf("[blocklist] '%s'", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		line := scanner.Text()
		if !commentsRE.Match([]byte(line)) {
			key := strings.ToLower(line)
			h.list[dns.Fqdn(key)] = true
		}
	}
	log.Info().Msgf("[blocklist] '%s' loaded as blacklist", path)
}

func (h *handler) addHTTP(uri string) {
	res, err := http.Get(uri)
	if err != nil {
		log.Warn().Msgf("cannot load blocklist: %s", uri)
		return
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		log.Warn().Msgf("cannot load blocklist: %s. Err: %s", uri, err)
		return
	}
	content := string(b)
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")

	for _, l := range lines {
		if !commentsRE.Match([]byte(l)) {
			key := strings.ToLower(l)
			h.list[dns.Fqdn(key)] = true
		}
	}
	log.Info().Msgf("[blocklist] '%s' loaded", uri)
}

func (h *handler) ServeDNS(c context.Context, r *pigdns.Request) {
	allowed := true

	key := strings.ToLower(r.Name())

	if _, ok := h.list[key]; ok {
		allowed = false
	}

	if !allowed {
		log.Printf("[blocklist] domain '%s' is not allowed", r.Name())
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
