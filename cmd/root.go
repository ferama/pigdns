package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/ferama/pigdns/pkg/certman"
	"github.com/ferama/pigdns/pkg/server"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/ferama/pigdns/pkg/web"
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
	rootCmd.Flags().Bool(utils.Debug, false, "enable debug")
	viper.BindPFlag(utils.Debug, rootCmd.Flags().Lookup(utils.Debug))
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
  PIGDNS_RESOLVER_ALLOW_NETS="127.0.0.1/32 192.168.10.0/24" pigdns -r ...

Or with multiple flags:
  pigdns -d pig.io -r --resolver-allow-nets "192.168.10.0/24" --resolver-allow-nets "127.0.0.1/32"
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
	rootCmd.Flags().BoolP(utils.WebEnableFlag, "w", false, "if to enable web server (for certs and doh)")
	viper.BindPFlag(utils.WebEnableFlag, rootCmd.Flags().Lookup(utils.WebEnableFlag))

	rootCmd.Flags().StringP(utils.WebApiKeyFlag, "k", "", "use an api key to download certs. if empty no protection will be enabled")
	viper.BindPFlag(utils.WebApiKeyFlag, rootCmd.Flags().Lookup(utils.WebApiKeyFlag))

	rootCmd.Flags().StringP(utils.WebSubdomainFlag, "b", "",
		`use a dubdomain to enable https (we have valid certs for subdomains only). You should
enable the zone file too (--zone-file flag) and register the subdomain. usually 'www' is used`)
	viper.BindPFlag(utils.WebSubdomainFlag, rootCmd.Flags().Lookup(utils.WebSubdomainFlag))
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
		debug := viper.GetBool(utils.Debug)

		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		if debug {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}

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

		if !domainEnable && !resolverEnable {
			cmd.Help()
			os.Exit(1)
		}

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

		s := server.NewServer(port, domain, resolverEnable, datadir)
		s.Start()
	},
}

// Execute executes the root command
func Execute() error {
	return rootCmd.Execute()
}
