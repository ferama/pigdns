package forward

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

const dialTimeout = 8 * time.Second

type Handler struct {
	Next dns.Handler
}

func (h *Handler) getAnswer(m *dns.Msg, net string, nsaddr string) error {
	client := &dns.Client{
		Timeout: dialTimeout,
		Net:     net,
	}

	resp, _, err := client.Exchange(m, nsaddr)
	if err != nil {
		return err

	}

	log.Println("[forward] quering ns", nsaddr)
	if resp.Truncated {
		return h.getAnswer(m, "tcp", nsaddr)
	}

	if !resp.Authoritative && len(resp.Ns) > 0 {
		n := rand.Intn(len(resp.Ns))
		rr := resp.Ns[n]
		ns := rr.(*dns.NS)
		addr := fmt.Sprintf("%s:53", ns.Ns)
		return h.getAnswer(m, net, addr)
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

	// nsaddr := fmt.Sprintf("%s:53", upstream[0])
	nsaddr := fmt.Sprintf("%s:53", getRootNS())
	err = h.getAnswer(m, "udp", nsaddr)
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
