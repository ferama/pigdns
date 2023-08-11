package regexip

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/ferama/pigdns/pkg/handlers/collector"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/miekg/dns"
)

const handlerName = "regexip"

var (
	// 192-168-10-1.pigdns.io
	// aa-192-168-10-1.pigdns.io
	ipv4REDashes = regexp.MustCompile(`(^|[.-])(((25[0-5]|(2[0-4]|1?\d)?\d)-){3}(25[0-5]|(2[0-4]|1?\d)?\d))($|[.-])`)

	// 2a01-4f8-c17-b8f--2.pigdns.io
	// dig @localhost 2a01-4f8-c17-b8f--2.pigdns.io AAAA
	ipv6RE = regexp.MustCompile(`(^|[.-])(([[:xdigit:]]{1,4}-){7}[[:xdigit:]]{1,4}|([[:xdigit:]]{1,4}-){1,7}-|([[:xdigit:]]{1,4}-){1,6}-[[:xdigit:]]{1,4}|([[:xdigit:]]{1,4}-){1,5}(-[[:xdigit:]]{1,4}){1,2}|([[:xdigit:]]{1,4}-){1,4}(-[[:xdigit:]]{1,4}){1,3}|([[:xdigit:]]{1,4}-){1,3}(-[[:xdigit:]]{1,4}){1,4}|([[:xdigit:]]{1,4}-){1,2}(-[[:xdigit:]]{1,4}){1,5}|[[:xdigit:]]{1,4}-((-[[:xdigit:]]{1,4}){1,6})|-((-[[:xdigit:]]{1,4}){1,7}|-)|fe80-(-[[:xdigit:]]{0,4}){0,4}%[\da-zA-Z]+|--(ffff(-0{1,4})?-)?((25[0-5]|(2[0-4]|1?\d)?\d)\.){3}(25[0-5]|(2[0-4]|1?\d)?\d)|([[:xdigit:]]{1,4}-){1,4}-((25[0-5]|(2[0-4]|1?\d)?\d)\.){3}(25[0-5]|(2[0-4]|1?\d)?\d))($|[.-])`)
)

type Handler struct {
	Next pigdns.Handler
}

func (h *Handler) getA(name string) (net.IP, error) {
	fqdn := []byte(name)

	var ipv4address net.IP
	if ipv4REDashes.Match(fqdn) {
		match := string(ipv4REDashes.FindSubmatch(fqdn)[2])
		match = strings.Replace(match, "-", ".", -1)
		ipv4address = net.ParseIP(match).To4()
		if ipv4address == nil {
			return ipv4address, fmt.Errorf("should be valid A but isn't: %s", fqdn)
		}
		return ipv4address, nil

	}
	return ipv4address, fmt.Errorf("should be valid A but isn't: %s", fqdn)
}

func (h *Handler) getAAAA(name string) (net.IP, error) {
	fqdn := []byte(name)

	var ipv16address net.IP
	if !ipv6RE.Match(fqdn) {
		return ipv16address, fmt.Errorf("should be valid AAAA but isn't: %s", fqdn)
	}

	ipv6RE.Longest()
	match := string(ipv6RE.FindSubmatch(fqdn)[2])
	match = strings.Replace(match, "-", ":", -1)
	ipv16address = net.ParseIP(match).To16()
	if ipv16address == nil {
		return ipv16address, fmt.Errorf("should be valid AAAA but isn't: %s", fqdn)
	}

	return ipv16address, nil
}

// returns a log message
func (h *Handler) parseQuery(m *dns.Msg, r *pigdns.Request) string {
	logMsg := ""
	// for _, q := range m.Question {
	logMsg = fmt.Sprintf("%s[regexip] query=%s", logMsg, r.Name())
	var ip net.IP
	var err error

	typeSring := ""

	switch r.QType() {
	case dns.TypeA:
		ip, err = h.getA(r.Name())
		typeSring = "A"
	case dns.TypeAAAA:
		ip, err = h.getAAAA(r.Name())
		typeSring = "AAAA"
	default:
		logMsg = fmt.Sprintf("%s answer=no-answer", logMsg)
	}

	if err == nil {
		rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", r.Name(), typeSring, ip))
		if err == nil {
			m.Answer = append(m.Answer, rr)
			logMsg = fmt.Sprintf("%s answer=%s", logMsg, ip)
		}
	} else {
		logMsg = fmt.Sprintf("%s answer=no-answer", logMsg)
	}
	if len(m.Answer) == 0 {
		return logMsg
	}
	return logMsg
}

func (h *Handler) ServeDNS(c context.Context, r *pigdns.Request) {
	m := new(dns.Msg)
	m.SetReply(r.Msg)
	m.Authoritative = true

	logMsg := ""

	if r.Msg.Opcode != dns.OpcodeQuery {
		h.Next.ServeDNS(c, r)
		return
	}

	logMsg = h.parseQuery(m, r)

	log.Print(logMsg)
	if len(m.Answer) != 0 {
		cc := c.Value(collector.CollectorContextKey).(*collector.CollectorContext)
		cc.AnweredBy = handlerName
		m.Rcode = dns.RcodeSuccess
		r.ResponseWriter.WriteMsg(m)
		return
	}

	h.Next.ServeDNS(c, r)
}
