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
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/ferama/pigdns/pkg/web"
	"github.com/ferama/pigdns/pkg/zone"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	DomainFlag = "domain"
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
	rootCmd.Flags().StringP(utils.DatadirFlag, "a", ".", "data dir where pigdns data will be stored")
	viper.BindPFlag(utils.DatadirFlag, rootCmd.Flags().Lookup(utils.DatadirFlag))

	// dns server
	rootCmd.Flags().StringP(utils.DomainFlag, "d", "", "the pigdns domain")
	viper.BindPFlag(utils.DomainFlag, rootCmd.Flags().Lookup(utils.DomainFlag))

	rootCmd.Flags().IntP(utils.PortFlag, "p", 53, "listen port")
	viper.BindPFlag(utils.PortFlag, rootCmd.Flags().Lookup(utils.PortFlag))

	rootCmd.Flags().StringP(utils.ZoneFileFlag, "z", "", "zone file")
	viper.BindPFlag(utils.ZoneFileFlag, rootCmd.Flags().Lookup(utils.ZoneFileFlag))

	rootCmd.Flags().BoolP(utils.ForwarderEnableFlag, "f", false, "if true, forwards not managed zones to general public dns")
	viper.BindPFlag(utils.ForwarderEnableFlag, rootCmd.Flags().Lookup(utils.ForwarderEnableFlag))

	// cert
	rootCmd.Flags().StringP(utils.CertmanEmailFlag, "e", "user@not-exists.com", "let's encrypt will use this to contact you about expiring certificate")
	viper.BindPFlag(utils.CertmanEmailFlag, rootCmd.Flags().Lookup(utils.CertmanEmailFlag))

	rootCmd.Flags().BoolP(utils.CertmanUseStagingFlag, "s", false, "use staging let's encrypt api")
	viper.BindPFlag(utils.CertmanUseStagingFlag, rootCmd.Flags().Lookup(utils.CertmanUseStagingFlag))

	rootCmd.Flags().BoolP(utils.CertmanEnableFlag, "c", false, "enable certmanager")
	viper.BindPFlag(utils.CertmanEnableFlag, rootCmd.Flags().Lookup(utils.CertmanEnableFlag))

	// web
	rootCmd.Flags().BoolP(utils.WebEnableFlag, "w", false, "if to enable web ui")
	viper.BindPFlag(utils.WebEnableFlag, rootCmd.Flags().Lookup(utils.WebEnableFlag))

	rootCmd.Flags().StringP(utils.WebApiKeyFlag, "k", "", "use an api key to download certs. if empty no protection will be enabled")
	viper.BindPFlag(utils.WebApiKeyFlag, rootCmd.Flags().Lookup(utils.WebApiKeyFlag))

	rootCmd.Flags().StringP(utils.WebSubdomainFlag, "b", "",
		`use a dubdomain to enable https (we have valid certs for subdomains only). You should
enable the zone file too (--zone-file flag) and register the subdomain. usually 'www' is used`)
	viper.BindPFlag(utils.WebSubdomainFlag, rootCmd.Flags().Lookup(utils.WebSubdomainFlag))
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

	zoneFilePath := viper.GetString(utils.ZoneFileFlag)

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
		domain := viper.GetString(utils.DomainFlag)

		if domain == "" {
			fmt.Printf("ERROR: domain is required\n\n")
			cmd.Help()
			os.Exit(1)
		}

		email := viper.GetString(utils.CertmanEmailFlag)
		datadir := viper.GetString(utils.DatadirFlag)
		port := viper.GetInt(utils.PortFlag)

		webEnable := viper.GetBool(utils.WebEnableFlag)
		webSubdomain := viper.GetString(utils.WebSubdomainFlag)
		webApikey := viper.GetString(utils.WebApiKeyFlag)
		certmanUseStaging := viper.GetBool(utils.CertmanUseStagingFlag)

		forwarderEnable := viper.GetBool(utils.ForwarderEnableFlag)

		certmanEnable := viper.GetBool(utils.CertmanEnableFlag)
		if certmanEnable {
			cm := certman.New(domain, datadir, email, certmanUseStaging)
			go cm.Run()
		}

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
