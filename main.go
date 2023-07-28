package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

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
	// common
	rootCmd.Flags().StringP("datadir", "a", ".", "data dir where pigdns data will be stored")

	// dns server
	rootCmd.Flags().StringP("domain", "d", "", "the pigdns domain")
	rootCmd.MarkFlagRequired("domain")
	rootCmd.Flags().IntP("port", "p", 53, "udp listen port")
	rootCmd.Flags().StringP("ns-record", "n", "", "[optional] how to answer to NS queries for the domain")
	// pigdns ... -i 192.168.10.1 -i 127.0.0.1
	rootCmd.Flags().StringArrayP("ns-ips", "i", []string{}, "[optional] how to answer to A and AAAA queries for the domain")

	// cert
	rootCmd.Flags().StringP("email", "e", "user@not-exists.com", "let's encrypt will use this to contact you about expiring certificate")
	rootCmd.Flags().BoolP("certman-use-staging", "s", false, "use staging let's encrypt api")

	// web
	rootCmd.Flags().BoolP("enable-web", "w", false, "if to enable web ui")
}

func rootHandler(nsRecord string, nsIPs []string) dns.HandlerFunc {
	IPv4s := []string{}
	IPv6s := []string{}
	for _, ip := range nsIPs {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			log.Fatalf("[root] %s is not a valid ip address", ip)
		}
		if strings.Contains(string(parsedIP), ":") {
			IPv6s = append(IPv6s, parsedIP.String())
		} else {
			IPv4s = append(IPv4s, parsedIP.String())
		}

	}

	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		if r.Opcode != dns.OpcodeQuery {
			return
		}
		logMsg := ""

		havHanswer := false
		for _, q := range m.Question {
			logMsg = fmt.Sprintf("%s[root] query=%s", logMsg, q.String())

			switch q.Qtype {
			case dns.TypeNS:
				if nsRecord != "" {
					rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", q.Name, "NS", nsRecord))
					if err == nil {
						m.Answer = append(m.Answer, rr)
						havHanswer = true
						logMsg = fmt.Sprintf("%s answer=%s", logMsg, nsRecord)
					}
				}
			case dns.TypeA:
				for _, ip := range IPv4s {
					rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", q.Name, "A", ip))
					if err == nil {
						m.Answer = append(m.Answer, rr)
						havHanswer = true
						logMsg = fmt.Sprintf("%s answer=%s", logMsg, ip)
					}
				}
			case dns.TypeAAAA:
				for _, ip := range IPv6s {
					rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", q.Name, "AAAA", ip))
					if err == nil {
						m.Answer = append(m.Answer, rr)
						havHanswer = true
						logMsg = fmt.Sprintf("%s answer=%s", logMsg, ip)
					}
				}
			}
		}
		if !havHanswer {
			rr, _ := dns.NewRR(defaultRes)
			m.Answer = append(m.Answer, rr)
			logMsg = fmt.Sprintf("%s answer=no-answer", logMsg)

		}

		log.Println(logMsg)

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

		enableWeb, _ := cmd.Flags().GetBool("enable-web")
		certmanUseStaging, _ := cmd.Flags().GetBool("certman-use-staging")

		cm := certman.New(domain, datadir, email, certmanUseStaging)
		go cm.Run()

		if enableWeb {
			ws := web.NewWebServer(datadir, domain)
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
