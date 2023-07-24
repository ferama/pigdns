package main

import (
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/ferama/pigdns/pkg/acmec"
	"github.com/ferama/pigdns/pkg/certman"
	"github.com/ferama/pigdns/pkg/regexip"
	"github.com/ferama/pigdns/pkg/web"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

const (
	defaultRes = "pigdns.io. 1800 IN SOA pigdns.io. pigdns.io. 1502165581 14400 3600 604800 14400"
)

func init() {
	rootCmd.Flags().StringP("domain", "d", "", "the pigdns domain")
	rootCmd.MarkFlagRequired("domain")

	rootCmd.Flags().StringP("email", "e", "user@not-exists.com", "let's encrypt will use this to contact you about expiring certificate")
	rootCmd.Flags().StringP("datadir", "a", ".", "data dir where pigdns data will be stored")
	rootCmd.Flags().IntP("port", "p", 53, "udp listen port")

	rootCmd.Flags().BoolP("webenable", "w", false, "if to enable web ui")

	rootCmd.Flags().StringP("ns-record", "n", "", "[optional] how to answer to NS queries for the domain")

	// pigdns ... -i 192.168.10.1 -i 127.0.0.1
	rootCmd.Flags().StringArrayP("ns-ips", "i", []string{}, "[optional] how to answer to A and AAAA queries for the domain")
}

func rootHandler(nsRecord string, nsIPs []string) dns.HandlerFunc {
	for _, ip := range nsIPs {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			log.Fatalf("[root] %s is not a valid ip address", ip)
		}
		// TODO: detect if is IPv4 or IPv6 and aswer
		// with A or AAAA
	}

	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		if r.Opcode != dns.OpcodeQuery {
			return
		}

		havHanswer := false
		for _, q := range m.Question {
			switch q.Qtype {
			case dns.TypeNS:
				if nsRecord != "" {
					rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", q.Name, "NS", nsRecord))
					if err == nil {
						m.Answer = append(m.Answer, rr)
						havHanswer = true
					}
				}
			}
		}
		if !havHanswer {
			rr, _ := dns.NewRR(defaultRes)
			m.Answer = append(m.Answer, rr)
		}

		w.WriteMsg(m)
	}
}

// the first handler that write back to the client calling
// w.WriteMsg(m) win. No other handler can write back anymore
// Chain rings are called in reverse order
func buildChain(cmd *cobra.Command) dns.Handler {
	var chain dns.Handler

	nsRecord, _ := cmd.Flags().GetString("ns-record")
	nsIps, _ := cmd.Flags().GetStringArray("ns-ips")

	// leaf handler (is the latest one)
	chain = dns.HandlerFunc(rootHandler(nsRecord, nsIps))

	chain = &regexip.Handler{Next: chain}
	chain = &acmec.Handler{Next: chain}

	return chain
}

var rootCmd = &cobra.Command{
	Use:  "pigdns",
	Long: "dynamic dns resolver",
	Run: func(cmd *cobra.Command, args []string) {
		domain, _ := cmd.Flags().GetString("domain")
		email, _ := cmd.Flags().GetString("email")
		datadir, _ := cmd.Flags().GetString("datadir")
		port, _ := cmd.Flags().GetInt("port")

		webenable, _ := cmd.Flags().GetBool("webenable")

		cm := certman.New(domain, datadir, email)
		go cm.Run()

		if webenable {
			ws := web.NewWebServer(datadir)
			go ws.Run()
		}

		// attach request handler func
		dns.Handle(fmt.Sprintf("%s.", domain), buildChain(cmd))

		// start server
		server := &dns.Server{
			Addr: ":" + strconv.Itoa(port),
			Net:  "udp",
		}
		log.Printf("listening on ':%d'", port)

		err := server.ListenAndServe()
		defer server.Shutdown()
		if err != nil {
			log.Fatalf("failed to start server: %s\n ", err.Error())
		}
	},
}

func main() {
	rootCmd.Execute()
}
