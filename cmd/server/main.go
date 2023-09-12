package main

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
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)

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
	rootCmd.Flags().Bool(DebugFlag, false, "enable debug")
	viper.BindPFlag(DebugFlag, rootCmd.Flags().Lookup(DebugFlag))
	rootCmd.Flags().Bool(InfoFlag, false, "enable info log level")
	viper.BindPFlag(InfoFlag, rootCmd.Flags().Lookup(InfoFlag))
	rootCmd.Flags().StringP(DatadirFlag, "a", ".", "data dir where pigdns data will be stored")
	viper.BindPFlag(DatadirFlag, rootCmd.Flags().Lookup(DatadirFlag))

	// dns server
	rootCmd.Flags().Bool(DnsServeRecursorEnable, false, `if true and resolver is enabled, enable the standard dns server (tcp and udp) 
to serve the resolver requests. By default they are enabled in the DOH server only`)
	viper.BindPFlag(DnsServeRecursorEnable, rootCmd.Flags().Lookup(DnsServeRecursorEnable))

	rootCmd.Flags().StringP(DomainFlag, "d", "", "the pigdns domain")
	viper.BindPFlag(DomainFlag, rootCmd.Flags().Lookup(DomainFlag))

	rootCmd.Flags().StringP(ListenAddressFlag, "p", ":53", "dns listen address")
	viper.BindPFlag(ListenAddressFlag, rootCmd.Flags().Lookup(ListenAddressFlag))

	rootCmd.Flags().StringP(ZoneFileFlag, "z", "", "zone file")
	viper.BindPFlag(ZoneFileFlag, rootCmd.Flags().Lookup(ZoneFileFlag))

	// resolver
	rootCmd.Flags().BoolP(RecursorEnableFlag, "r", false, "if true, enable recursive resolver for not managed zones starting from root nameservers")
	viper.BindPFlag(RecursorEnableFlag, rootCmd.Flags().Lookup(RecursorEnableFlag))
	rootCmd.Flags().StringArray(RecursorAllowNetworks, []string{}, `sets a list of allowed networks. if empty no filter will be applied.
The list can be set using env var or multiple flags.
Example (with env var):
  PIGDNS_RESOLVER_ALLOW_NETS="127.0.0.1/32 192.168.10.0/24" pigdns -r ...

Or with multiple flags:
  pigdns -d pig.io -r --resolver-allow-nets "192.168.10.0/24" --resolver-allow-nets "127.0.0.1/32"
`)
	viper.BindPFlag(RecursorAllowNetworks, rootCmd.Flags().Lookup(RecursorAllowNetworks))

	// cert
	rootCmd.Flags().StringP(CertmanEmailFlag, "e", "user@not-exists.com", `
let's encrypt will use this address to contact you about expiring 
certificate`)
	viper.BindPFlag(CertmanEmailFlag, rootCmd.Flags().Lookup(CertmanEmailFlag))

	rootCmd.Flags().BoolP(CertmanUseStagingFlag, "s", false, "use staging let's encrypt api")
	viper.BindPFlag(CertmanUseStagingFlag, rootCmd.Flags().Lookup(CertmanUseStagingFlag))

	rootCmd.Flags().BoolP(CertmanEnableFlag, "c", false, `enable certmanager. to make it works pigdns tcp/udp server must listen on port 53 
and be reachable from the internet`)
	viper.BindPFlag(CertmanEnableFlag, rootCmd.Flags().Lookup(CertmanEnableFlag))

	// web
	rootCmd.Flags().BoolP(WebCertsEnableFlag, "w", false, "if to enable web server for certs serving")
	viper.BindPFlag(WebCertsEnableFlag, rootCmd.Flags().Lookup(WebCertsEnableFlag))

	rootCmd.Flags().StringP(WebCertsApiKeyFlag, "k", "", "use an api key to download certs. if empty no protection will be enabled")
	viper.BindPFlag(WebCertsApiKeyFlag, rootCmd.Flags().Lookup(WebCertsApiKeyFlag))

	rootCmd.Flags().BoolP(WebDohEnableFlag, "o", false, "if to enable web server for DNS over HTTPS (doh)")
	viper.BindPFlag(WebDohEnableFlag, rootCmd.Flags().Lookup(WebDohEnableFlag))
	rootCmd.Flags().Bool(WebHTTPSDisableFlag, false, "you should always use https. this flag is useful if you want to use external https termination")
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
		debug := viper.GetBool(DebugFlag)
		info := viper.GetBool(InfoFlag)

		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		if info {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
		}
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

		resolverEnable := viper.GetBool(RecursorEnableFlag)
		webHTTPSDisable := viper.GetBool(WebHTTPSDisableFlag)
		dnsServeResolverEnable := viper.GetBool(DnsServeRecursorEnable)

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

		// TODO:
		// dns server and doh server should use different dnsMux
		// The dns server should not use the resolver handler (is very dangerous) unless
		// it is forced too with an optional flag
		// The doh mux instead could use it more safely
		dnsMux := dns.NewServeMux()
		dohMux := dns.NewServeMux()
		if domainEnable {
			h := server.BuildDomainHandler(
				viper.GetString(ZoneFileFlag),
				domain,
				viper.GetBool(CertmanEnableFlag),
			)
			pigdns.HandleMux(dns.Fqdn(domain), h, dnsMux, false)
			pigdns.HandleMux(dns.Fqdn(domain), h, dohMux, true)
		}
		if resolverEnable {
			h := server.BuildResolverHandler(datadir, viper.GetStringSlice(RecursorAllowNetworks))
			if dnsServeResolverEnable {
				pigdns.HandleMux(".", h, dnsMux, false)
			}
			pigdns.HandleMux(".", h, dohMux, true)
		}

		var wg sync.WaitGroup
		if webCertsEnable || webDohEnable {
			ws := web.NewWebServer(
				dohMux,
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

		s := server.NewServer(dnsMux, listenAddress)
		wg.Add(1)
		go func() {
			s.Start()
			wg.Done()
		}()

		wg.Wait()
	},
}

func main() {
	rootCmd.Execute()
}
