package main

import (
	"fmt"
	"log"
	"strconv"

	"github.com/ferama/pigdns/pkg/acmec"
	"github.com/ferama/pigdns/pkg/certman"
	"github.com/ferama/pigdns/pkg/regexip"
	"github.com/ferama/pigdns/pkg/web"
	"github.com/ferama/pigdns/pkg/zone"
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
	rootCmd.Flags().StringP("zone-file", "z", "", "zone file")

	// cert
	rootCmd.Flags().StringP("email", "e", "user@not-exists.com", "let's encrypt will use this to contact you about expiring certificate")
	rootCmd.Flags().BoolP("certman-use-staging", "s", false, "use staging let's encrypt api")

	// web
	rootCmd.Flags().BoolP("web-enable", "w", false, "if to enable web ui")
	rootCmd.Flags().BoolP("web-https", "t", false, "if to enable web https")
}

func rootHandler() dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		if r.Opcode != dns.OpcodeQuery {
			return
		}
		logMsg := ""

		rr, _ := dns.NewRR(defaultRes)
		m.Answer = append(m.Answer, rr)
		logMsg = fmt.Sprintf("%s answer=no-answer", logMsg)

		log.Println(logMsg)
		w.WriteMsg(m)
	}
}

// the first handler that write back to the client calling
// w.WriteMsg(m) win. No other handler can write back anymore
// Chain rings are called in reverse order
func buildChain(cmd *cobra.Command) dns.Handler {
	var chain dns.Handler

	domain, _ := cmd.Flags().GetString("domain")
	zoneFile, _ := cmd.Flags().GetString("zone-file")

	// leaf handler (is the latest one)
	chain = dns.HandlerFunc(rootHandler())

	chain = &regexip.Handler{Next: chain}
	chain = zone.New(chain, domain, zoneFile)
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

		webEnable, _ := cmd.Flags().GetBool("web-enable")
		webHTTPS, _ := cmd.Flags().GetBool("web-https")
		certmanUseStaging, _ := cmd.Flags().GetBool("certman-use-staging")

		cm := certman.New(domain, datadir, email, certmanUseStaging)
		go cm.Run()

		if webEnable {
			ws := web.NewWebServer(datadir, domain, webHTTPS)
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
