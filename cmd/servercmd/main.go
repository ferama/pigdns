package servercmd

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/ferama/pigdns/pkg/certman"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/server"
	"github.com/ferama/pigdns/pkg/web"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

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
	rootCmd.Flags().Bool(Debug, false, "enable debug")
	viper.BindPFlag(Debug, rootCmd.Flags().Lookup(Debug))
	rootCmd.Flags().StringP(DatadirFlag, "a", ".", "data dir where pigdns data will be stored")
	viper.BindPFlag(DatadirFlag, rootCmd.Flags().Lookup(DatadirFlag))

	// dns server
	rootCmd.Flags().BoolP(DnsEnable, "n", false, "if true enable the standard dns server (tcp and udp)")
	viper.BindPFlag(DnsEnable, rootCmd.Flags().Lookup(DnsEnable))

	rootCmd.Flags().StringP(DomainFlag, "d", "", "the pigdns domain")
	viper.BindPFlag(DomainFlag, rootCmd.Flags().Lookup(DomainFlag))

	rootCmd.Flags().StringP(ListenAddressFlag, "p", ":53", "dns listen address")
	viper.BindPFlag(ListenAddressFlag, rootCmd.Flags().Lookup(ListenAddressFlag))

	rootCmd.Flags().StringP(ZoneFileFlag, "z", "", "zone file")
	viper.BindPFlag(ZoneFileFlag, rootCmd.Flags().Lookup(ZoneFileFlag))

	// resolver
	rootCmd.Flags().BoolP(ResolverEnableFlag, "r", false, "if true, resolve not managed zones starting from root ns")
	viper.BindPFlag(ResolverEnableFlag, rootCmd.Flags().Lookup(ResolverEnableFlag))
	rootCmd.Flags().StringArray(ResolverAllowNetworks, []string{}, `sets a list of allowed networks. if empty no filter will be applied.
The list can be set using env var or multiple flags.
Example (with env var):
  PIGDNS_RESOLVER_ALLOW_NETS="127.0.0.1/32 192.168.10.0/24" pigdns -r ...

Or with multiple flags:
  pigdns -d pig.io -r --resolver-allow-nets "192.168.10.0/24" --resolver-allow-nets "127.0.0.1/32"
`)
	viper.BindPFlag(ResolverAllowNetworks, rootCmd.Flags().Lookup(ResolverAllowNetworks))

	// cert
	rootCmd.Flags().StringP(CertmanEmailFlag, "e", "user@not-exists.com", `
let's encrypt will use this address to contact you about expiring 
certificate`)
	viper.BindPFlag(CertmanEmailFlag, rootCmd.Flags().Lookup(CertmanEmailFlag))

	rootCmd.Flags().BoolP(CertmanUseStagingFlag, "s", false, "use staging let's encrypt api")
	viper.BindPFlag(CertmanUseStagingFlag, rootCmd.Flags().Lookup(CertmanUseStagingFlag))

	rootCmd.Flags().BoolP(CertmanEnableFlag, "c", false, "enable certmanager. to make it works pigdns must listen on port 53 and reachable from the internet")
	viper.BindPFlag(CertmanEnableFlag, rootCmd.Flags().Lookup(CertmanEnableFlag))

	// web
	rootCmd.Flags().BoolP(WebCertsEnableFlag, "w", false, "if to enable web server for certs serving")
	viper.BindPFlag(WebCertsEnableFlag, rootCmd.Flags().Lookup(WebCertsEnableFlag))

	rootCmd.Flags().StringP(WebCertsApiKeyFlag, "k", "", "use an api key to download certs. if empty no protection will be enabled")
	viper.BindPFlag(WebCertsApiKeyFlag, rootCmd.Flags().Lookup(WebCertsApiKeyFlag))

	rootCmd.Flags().BoolP(WebDohEnableFlag, "o", false, "if to enable web server for doh")
	viper.BindPFlag(WebDohEnableFlag, rootCmd.Flags().Lookup(WebDohEnableFlag))
	rootCmd.Flags().Bool(WebHTTPSDisableFlag, false, "you should always use https. this flag is usefull if you want to use external https termination")
	viper.BindPFlag(WebHTTPSDisableFlag, rootCmd.Flags().Lookup(WebHTTPSDisableFlag))
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
		debug := viper.GetBool(Debug)

		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		if debug {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}

		domain := viper.GetString(DomainFlag)

		domainEnable := domain != ""

		email := viper.GetString(CertmanEmailFlag)
		datadir := viper.GetString(DatadirFlag)
		listenAddress := viper.GetString(ListenAddressFlag)

		webCertsEnable := viper.GetBool(WebCertsEnableFlag)
		webCertsApikey := viper.GetString(WebCertsApiKeyFlag)
		webDohEnable := viper.GetBool(WebDohEnableFlag)
		certmanUseStaging := viper.GetBool(CertmanUseStagingFlag)

		resolverEnable := viper.GetBool(ResolverEnableFlag)
		dnsEnable := viper.GetBool(DnsEnable)
		webHTTPSDisable := viper.GetBool(WebHTTPSDisableFlag)

		if !domainEnable && !resolverEnable {
			failWithHelp(cmd, "you need to enable at least one of domain related functionalities (domanin flag) or recursor")
		}

		certmanEnable := viper.GetBool(CertmanEnableFlag)
		if certmanEnable && !domainEnable {
			failWithHelp(cmd, "cannot enable certman without a domain. please set the 'domain' flag")
		}
		if certmanEnable {
			cm := certman.New(domain, datadir, email, certmanUseStaging)
			go cm.Run()
		}

		if webCertsEnable && !domainEnable {
			failWithHelp(cmd, "cannot enable web certs without a domain. please set the 'domain' flag")
		}

		if domainEnable {
			h := server.BuildDomainHandler(
				viper.GetString(ZoneFileFlag),
				domain,
				viper.GetBool(CertmanEnableFlag),
			)
			pigdns.Handle(dns.Fqdn(domain), h)
		}
		if resolverEnable {
			h := server.BuildResolverHandler(datadir, viper.GetStringSlice(ResolverAllowNetworks))
			pigdns.Handle(".", h)
		}

		var wg sync.WaitGroup
		if webCertsEnable || webDohEnable {
			ws := web.NewWebServer(
				dns.DefaultServeMux,
				datadir,
				domain,
				webCertsEnable,
				webCertsApikey,
				webDohEnable,
				!webHTTPSDisable,
			)
			wg.Add(1)
			go func() {
				ws.Start()
				wg.Done()
			}()
		}

		if dnsEnable {
			s := server.NewServer(listenAddress, dns.DefaultServeMux)
			wg.Add(1)
			go func() {
				s.Start()
				wg.Done()
			}()
		}

		wg.Wait()
	},
}

// Execute executes the root command
func Execute() error {
	return rootCmd.Execute()
}
