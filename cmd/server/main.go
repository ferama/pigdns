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
)

func init() {
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
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
		conf := loadConf("./pigdns.yaml", true)
		fmt.Println("################")
		fmt.Printf("%s\n", conf.LogLevel)
		os.Exit(1)

		debug := strings.EqualFold(conf.LogLevel, "debug")
		info := strings.EqualFold(conf.LogLevel, "info")

		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		if info {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
		}
		if debug {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}

		domain := conf.Domain

		domainEnable := domain != ""

		email := conf.Certman.Email
		datadir := conf.DataDir
		webCertsEnable := conf.Certman.WebCerts.Enabled
		webCertsApikey := conf.Certman.WebCerts.ApiKey

		webDohEnable := conf.DohChain.Enabled
		certmanUseStaging := conf.Certman.UseStaging

		// resolverEnable := viper.GetBool(RecursorEnableFlag)
		// webHTTPSDisable := viper.GetBool(WebHTTPSDisableFlag)
		// dnsServeResolverEnable := viper.GetBool(DnsServeRecursorEnable)

		// if !domainEnable && !resolverEnable {
		// 	failWithHelp(cmd, "you need to enable at least one of domain related functionalities (domanin flag) or recursor")
		// }

		certmanEnable := conf.Certman.Enabled
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
				conf.UDPTCPDnsChain.Middlewares.ZoneFile.Path,
				domain,
				conf.Certman.Enabled,
			)
			pigdns.HandleMux(dns.Fqdn(domain), h, dnsMux, false)
			pigdns.HandleMux(dns.Fqdn(domain), h, dohMux, true)
		}

		// if resolverEnable {
		// 	h := server.BuildRecursorHandler(datadir, viper.GetStringSlice(RecursorAllowNetworks))
		// 	if dnsServeResolverEnable {
		// 		pigdns.HandleMux(".", h, dnsMux, false)
		// 	}
		// 	pigdns.HandleMux(".", h, dohMux, true)
		// }

		var wg sync.WaitGroup
		if webCertsEnable || webDohEnable {
			ws := web.NewWebServer(
				dohMux,
				datadir,
				domain,
				webCertsEnable,
				webCertsApikey,
				webDohEnable,
				false,
			)
			wg.Add(1)
			go func() {
				ws.Start()
				wg.Done()
			}()
		}

		s := server.NewServer(dnsMux, conf.UDPTCPDnsChain.ListenAddress)
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
