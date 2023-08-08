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
	"github.com/ferama/pigdns/pkg/regexip"
	"github.com/ferama/pigdns/pkg/regexip/web"
	"github.com/ferama/pigdns/pkg/resolver"
	"github.com/ferama/pigdns/pkg/utils"
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
	rootCmd.Flags().StringP(utils.DatadirFlag, "a", ".", "data dir where pigdns data will be stored")
	viper.BindPFlag(utils.DatadirFlag, rootCmd.Flags().Lookup(utils.DatadirFlag))

	// dns server
	rootCmd.Flags().StringP(utils.DomainFlag, "d", "", "the pigdns domain")
	viper.BindPFlag(utils.DomainFlag, rootCmd.Flags().Lookup(utils.DomainFlag))

	rootCmd.Flags().IntP(utils.PortFlag, "p", 53, "listen port")
	viper.BindPFlag(utils.PortFlag, rootCmd.Flags().Lookup(utils.PortFlag))

	rootCmd.Flags().StringP(utils.ZoneFileFlag, "z", "", "zone file")
	viper.BindPFlag(utils.ZoneFileFlag, rootCmd.Flags().Lookup(utils.ZoneFileFlag))

	// resolver
	rootCmd.Flags().BoolP(utils.ResolverEnableFlag, "r", false, "if true, resolve not managed zones starting from root ns")
	viper.BindPFlag(utils.ResolverEnableFlag, rootCmd.Flags().Lookup(utils.ResolverEnableFlag))
	rootCmd.Flags().StringArray(utils.ResolverAllowNetworks, []string{}, `sets a list of allowed networks. if empty no filter will be applied.
The list can be set using env var or multiple flags.
Example (with env var):
  PIGDNS_RESOLVER_ALLOW_NETS="127.0.0.1/32 192.168.10.0/24" pigdns -f ...

Or with multiple flags:
  pigdns -d pig.io -f --resolver-allow-nets "192.168.10.0/24" --resolver-allow-nets "127.0.0.1/32"
`)
	viper.BindPFlag(utils.ResolverAllowNetworks, rootCmd.Flags().Lookup(utils.ResolverAllowNetworks))

	// cert
	rootCmd.Flags().StringP(utils.CertmanEmailFlag, "e", "user@not-exists.com", `
let's encrypt will use this address to contact you about expiring 
certificate`)
	viper.BindPFlag(utils.CertmanEmailFlag, rootCmd.Flags().Lookup(utils.CertmanEmailFlag))

	rootCmd.Flags().BoolP(utils.CertmanUseStagingFlag, "s", false, "use staging let's encrypt api")
	viper.BindPFlag(utils.CertmanUseStagingFlag, rootCmd.Flags().Lookup(utils.CertmanUseStagingFlag))

	rootCmd.Flags().BoolP(utils.CertmanEnableFlag, "c", false, "enable certmanager. to make it works pigdns must listen on port 53 and reachable from the internet")
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

func failWithHelp(cmd *cobra.Command, msg string) {
	fmt.Printf("ERROR: %s\n\n", msg)
	cmd.Help()
	os.Exit(1)
}

var rootCmd = &cobra.Command{
	Use:  "pigdns",
	Long: "dynamic dns resolver",
	Run: func(cmd *cobra.Command, args []string) {
		domain := viper.GetString(utils.DomainFlag)

		domainEnable := domain != ""

		email := viper.GetString(utils.CertmanEmailFlag)
		datadir := viper.GetString(utils.DatadirFlag)
		port := viper.GetInt(utils.PortFlag)

		webEnable := viper.GetBool(utils.WebEnableFlag)
		webSubdomain := viper.GetString(utils.WebSubdomainFlag)
		webApikey := viper.GetString(utils.WebApiKeyFlag)
		certmanUseStaging := viper.GetBool(utils.CertmanUseStagingFlag)

		resolverEnable := viper.GetBool(utils.ResolverEnableFlag)

		certmanEnable := viper.GetBool(utils.CertmanEnableFlag)
		if certmanEnable && !domainEnable {
			failWithHelp(cmd, "cannot enable certman without a domain. please set the 'domain' flag")
		}
		if certmanEnable {
			cm := certman.New(domain, datadir, email, certmanUseStaging)
			go cm.Run()
		}

		if webEnable && !domainEnable {
			failWithHelp(cmd, "cannot enable web without a domain. please set the 'domain' flag")
		}
		if webEnable {
			ws := web.NewWebServer(datadir, domain, webSubdomain, webApikey)
			go ws.Run()
		}

		if domainEnable {
			dns.Handle(fmt.Sprintf("%s.", domain), buildChain())
		}

		if resolverEnable {
			resolver := resolver.NewResolver(rootHandler())
			dns.Handle(".", resolver)
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
