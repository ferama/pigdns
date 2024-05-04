package blocklist

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/metrics"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
)

const (
	handlerName = "blocklist"
)

var (
	commentsRE = regexp.MustCompile(`^\s*#`)
	isHTTPRE   = regexp.MustCompile(`^http(s)?:\/\/`)
	isREGEXP   = regexp.MustCompile(`(^\s*regex\s*:\s*)`)
)

type handler struct {
	Next pigdns.Handler

	blacklist map[string]bool
	whitelist map[string]bool
	regexes   []*regexp.Regexp
}

func NewBlocklistHandler(blocklists []string, whitelists []string, next pigdns.Handler) *handler {
	h := &handler{
		Next: next,

		blacklist: map[string]bool{},
		whitelist: map[string]bool{},
		regexes:   make([]*regexp.Regexp, 0),
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
		h.buildWhiteList(u)
	}

	return h
}

func (h *handler) processLine(line string) {
	if !commentsRE.Match([]byte(line)) {
		if !isREGEXP.Match([]byte(line)) {
			key := strings.ToLower(line)
			h.blacklist[dns.Fqdn(key)] = true
		} else {
			exp := isREGEXP.ReplaceAllString(line, "")
			h.regexes = append(h.regexes, regexp.MustCompile(exp))
			log.Printf("regexp: %s", exp)
		}
	}
}

func (h *handler) buildWhiteList(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Warn().Msgf("[blocklist] '%s'", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// delete(h.blacklist, dns.Fqdn(line))
		if !commentsRE.Match([]byte(line)) {
			key := strings.ToLower(line)
			h.whitelist[dns.Fqdn(key)] = true
		}
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
		h.processLine(line)
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
		h.processLine(l)
	}
	log.Info().Msgf("[blocklist] '%s' loaded", uri)
}

func (h *handler) ServeDNS(c context.Context, r *pigdns.Request) {
	allowed := true

	key := strings.ToLower(r.Name())

	if _, ok := h.blacklist[key]; ok {
		allowed = false
	}

	for _, exp := range h.regexes {
		if exp.MatchString(key) {
			allowed = false
			break
		}
	}

	if _, ok := h.whitelist[key]; ok {
		allowed = true
	}

	if !allowed {
		metrics.Instance().QueriesBlocked.Inc()
		log.Printf("[blocklist] domain '%s' is not allowed", r.Name())
		if c.Value(collector.CollectorContextKey) != nil {
			cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
			cc.AnweredBy = handlerName
		}
		m := new(dns.Msg)

		null, _ := dns.NewRR(fmt.Sprintf("%s IN A 0.0.0.0", r.Name()))
		if r.QType() == dns.TypeAAAA {
			null, _ = dns.NewRR(fmt.Sprintf("%s IN AAAA ::", r.Name()))
		}
		null.Header().Ttl = 3600 * 3

		m.Answer = append(m.Answer, null)
		r.Reply(m)

		pc := c.Value(pigdns.PigContextKey).(*pigdns.PigContext)
		pc.Rcode = m.Rcode
		return
	}
	h.Next.ServeDNS(c, r)
}
