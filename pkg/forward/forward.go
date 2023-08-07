package forward

import (
	"fmt"
	"log"
	"time"

	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

const dialTimeout = 8 * time.Second

var upstream = []string{
	"1.1.1.1:53",
	"208.67.222.222:53",
	"208.67.220.220:53",
}

type Handler struct {
	Next dns.Handler
}

func (h *Handler) getAnswer(m *dns.Msg, net string) error {
	client := &dns.Client{
		Timeout: dialTimeout,
		Net:     net,
	}

	resp, _, err := client.Exchange(m, upstream[0])
	if err != nil {
		return err
	}

	if resp.Truncated {
		return h.getAnswer(m, "tcp")
	}

	m.Answer = append(m.Answer, resp.Answer...)
	return nil
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	allowedNets := viper.GetStringSlice(utils.ForwardAllowNetworks)
	allowed, err := utils.IsClientAllowed(w.RemoteAddr(), allowedNets)
	if err != nil {
		log.Fatal(err)
	}
	if !allowed {
		log.Printf("[forward] client '%s' is not allowed", w.RemoteAddr())
		h.Next.ServeDNS(w, r)
		return
	}

	m := new(dns.Msg)
	m.Authoritative = false
	m.RecursionDesired = true

	logMsg := ""

	q := r.Question[0]
	logMsg = fmt.Sprintf("%s[forward] query=%s", logMsg, q.String())

	m.SetQuestion(q.Name, q.Qtype)

	err = h.getAnswer(m, "udp")
	if err != nil {
		logMsg = fmt.Sprintf("%s %s", logMsg, err)
		log.Println(logMsg)
		h.Next.ServeDNS(w, r)
		return
	}

	m.SetReply(r)
	if len(m.Answer) != 0 {
		log.Println(logMsg)
		m.Rcode = dns.RcodeSuccess
		w.WriteMsg(m)
		return
	}

	h.Next.ServeDNS(w, r)
}
