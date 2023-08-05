package cmd

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/ferama/pigdns/pkg/acmec"
	"github.com/ferama/pigdns/pkg/certman"
	"github.com/ferama/pigdns/pkg/forward"
	"github.com/ferama/pigdns/pkg/regexip"
	"github.com/ferama/pigdns/pkg/web"
	"github.com/ferama/pigdns/pkg/zone"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)
	// this two lines enables set config through env vars.
	// you can use something like
	//	PIGDNS_YOURCONFVARHERE=YOURVALUE
	//
	// Flags always take precedence over env vars
	viper.AutomaticEnv()
	viper.SetEnvPrefix("pigdns")

	// common
	rootCmd.Flags().StringP("datadir", "a", ".", "data dir where pigdns data will be stored")
	viper.BindPFlag("datadir", rootCmd.Flags().Lookup("datadir"))

	// dns server
	rootCmd.Flags().StringP("domain", "d", "", "the pigdns domain")
	viper.BindPFlag("domain", rootCmd.Flags().Lookup("domain"))
	rootCmd.Flags().IntP("port", "p", 53, "listen port")
	viper.BindPFlag("port", rootCmd.Flags().Lookup("port"))
	rootCmd.Flags().StringP("zone-file", "z", "", "zone file")
	viper.BindPFlag("zone-file", rootCmd.Flags().Lookup("zone-file"))
	rootCmd.Flags().BoolP("forwarder-enable", "f", false, "if true, forwards not managed zones to general public dns")
	viper.BindPFlag("forwarder-enable", rootCmd.Flags().Lookup("forwarder-enable"))

	// cert
	rootCmd.Flags().StringP("email", "e", "user@not-exists.com", "let's encrypt will use this to contact you about expiring certificate")
	viper.BindPFlag("email", rootCmd.Flags().Lookup("email"))
	rootCmd.Flags().BoolP("certman-use-staging", "s", false, "use staging let's encrypt api")
	viper.BindPFlag("certman-use-staging", rootCmd.Flags().Lookup("certman-use-staging"))

	// web
	rootCmd.Flags().BoolP("web-enable", "w", false, "if to enable web ui")
	viper.BindPFlag("web-enable", rootCmd.Flags().Lookup("web-enable"))
	rootCmd.Flags().StringP("web-apikey", "k", "", "use an api key to download certs. if empty no protection will be enabled")
	viper.BindPFlag("web-apikey", rootCmd.Flags().Lookup("web-apikey"))
	rootCmd.Flags().StringP("web-subdomain", "b", "",
		`use a dubdomain to enable https (we have valid certs for subdomains only). You should
enable the zone file too (--zone-file flag) and register the subdomain. usually 'www' is used`)
	viper.BindPFlag("web-subdomain", rootCmd.Flags().Lookup("web-subdomain"))
}

func rootHandler() dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		logMsg := ""
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Rcode = dns.RcodeSuccess

		for _, q := range m.Question {
			logMsg = fmt.Sprintf("%s[root] query=%s", logMsg, q.String())
		}

		if r.Opcode != dns.OpcodeQuery {
			return
		}

		rr := zone.GetSOArecord()
		m.Answer = append(m.Answer, rr)

		logMsg = fmt.Sprintf("%s answer=%s", logMsg, rr)
		log.Println(logMsg)

		w.WriteMsg(m)
	}
}

// the first handler that write back to the client calling
// w.WriteMsg(m) win. No other handler can write back anymore
// Chain rings are called in reverse order
func buildChain() dns.Handler {
	var chain dns.Handler

	zoneFilePath := viper.GetString("zone-file")

	// leaf handler (is the latest one)
	chain = dns.HandlerFunc(rootHandler())

	chain = &regexip.Handler{Next: chain}
	if zoneFilePath != "" {
		chain = zone.New(chain)
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
		domain := viper.GetString("domain")

		if domain == "" {
			fmt.Printf("ERROR: domain is required\n\n")
			cmd.Help()
			os.Exit(1)
		}

		email := viper.GetString("email")
		datadir := viper.GetString("datadir")
		port := viper.GetInt("port")

		webEnable := viper.GetBool("web-enable")
		webSubdomain := viper.GetString("web-subdomain")
		webApikey := viper.GetString("web-apikey")
		certmanUseStaging := viper.GetBool("certman-use-staging")

		forwarderEnable := viper.GetBool("forwarder-enable")

		cm := certman.New(domain, datadir, email, certmanUseStaging)
		go cm.Run()

		if webEnable {
			ws := web.NewWebServer(datadir, domain, webSubdomain, webApikey)
			go ws.Run()
		}

		dns.Handle(fmt.Sprintf("%s.", domain), buildChain())

		if forwarderEnable {
			dns.Handle(".", &forward.Handler{
				Next: dns.HandlerFunc(rootHandler()),
			})
		}

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

// Execute executes the root command
func Execute() error {
	return rootCmd.Execute()
}
