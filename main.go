package main

import (
	"fmt"
	"log"
	"strconv"
	"sync"

	"github.com/ferama/pigdns/pkg/acmec"
	"github.com/ferama/pigdns/pkg/certman"
	"github.com/ferama/pigdns/pkg/regexip"
	"github.com/ferama/pigdns/pkg/web"
	"github.com/ferama/pigdns/pkg/zone"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

const (
	defaultRes = "github.com/ferama/pigdns. 1800 IN SOA github.com/ferama/pigdns. github.com/ferama/pigdns. 1502165581 14400 3600 604800 14400"
)

func init() {
	// common
	rootCmd.Flags().StringP("datadir", "a", ".", "data dir where pigdns data will be stored")

	// dns server
	rootCmd.Flags().StringP("domain", "d", "", "the pigdns domain")
	rootCmd.MarkFlagRequired("domain")
	rootCmd.Flags().IntP("port", "p", 53, "listen port")
	rootCmd.Flags().StringP("zone-file", "z", "", "zone file")

	// cert
	rootCmd.Flags().StringP("email", "e", "user@not-exists.com", "let's encrypt will use this to contact you about expiring certificate")
	rootCmd.Flags().BoolP("certman-use-staging", "s", false, "use staging let's encrypt api")

	// web
	rootCmd.Flags().BoolP("web-enable", "w", false, "if to enable web ui")
	rootCmd.Flags().StringP("web-subdomain", "b", "", "use a dubdomain to enable https (we have valid certs for subdomains only)")
}

func rootHandler() dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		if r.Opcode != dns.OpcodeQuery {
			return
		}
		rr, _ := dns.NewRR(defaultRes)
		m.Answer = append(m.Answer, rr)

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
	if zoneFile != "" {
		chain = zone.New(chain, domain, zoneFile)
	}
	chain = &acmec.Handler{Next: chain}

	return chain
}

func startServer(net string, port int) {
	server := &dns.Server{
		Addr: ":" + strconv.Itoa(port),
		Net:  net,
	}
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("failed to start server: %s\n ", err.Error())
	}
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
		webSubdomain, _ := cmd.Flags().GetString("web-subdomain")
		certmanUseStaging, _ := cmd.Flags().GetBool("certman-use-staging")

		cm := certman.New(domain, datadir, email, certmanUseStaging)
		go cm.Run()

		if webEnable {
			ws := web.NewWebServer(datadir, domain, webSubdomain)
			go ws.Run()
		}

		dns.Handle(fmt.Sprintf("%s.", domain), buildChain(cmd))

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			startServer("udp", port)
			wg.Done()
		}()

		wg.Add(1)
		go func() {
			startServer("tcp", port)
			wg.Done()
		}()

		log.Printf("listening on ':%d'", port)

		wg.Wait()
	},
}

func main() {
	rootCmd.Execute()
}
