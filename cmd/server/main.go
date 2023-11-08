package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ferama/pigdns/pkg/certman"
	"github.com/ferama/pigdns/pkg/metrics"
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
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		conf := loadConf(args[0])

		debug := strings.EqualFold(conf.LogLevel, "debug")
		info := strings.EqualFold(conf.LogLevel, "info")
		error := strings.EqualFold(conf.LogLevel, "error")

		if debug {
			output := zerolog.ConsoleWriter{Out: os.Stderr}
			output.FormatTimestamp = func(i interface{}) string {
				t, _ := time.Parse(time.RFC3339, i.(string))
				return t.Format("2006-01-02 15:04:05")
			}
			log.Logger = log.Output(output)
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}
		if info {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
		}
		if error {
			zerolog.SetGlobalLevel(zerolog.ErrorLevel)
		}

		if debug {
			conf.pprint()
		}

		certmanEnable := conf.Certman.Enabled
		if certmanEnable && !conf.Zone.Enabled {
			failWithHelp(cmd, "cannot enable certman without a zone conf")
		}
		if certmanEnable {
			cm := certman.New(
				conf.Zone.Name,
				conf.DataDir,
				conf.Certman.Email,
				conf.Certman.UseStaging,
			)
			go cm.Run()
		}

		var wg sync.WaitGroup

		dnsMux := dns.NewServeMux()
		dohMux := dns.NewServeMux()
		if conf.Recursor.Enabled {

			h := server.BuildRecursorHandler(
				conf.DataDir,
				conf.Recursor.AllowedNets,
				conf.Recursor.BlockLists,
				conf.Recursor.WhiteLists,
				conf.Recursor.CacheSize,
			)

			if conf.Recursor.ServeOnUDP {
				pigdns.HandleMux(".", h, dnsMux, false)
			}
			pigdns.HandleMux(".", h, dohMux, true)
		}

		zoneConf := conf.Zone
		if zoneConf.Enabled {
			h := server.BuildZoneHandler(
				zoneConf.ZoneFilePath,
				zoneConf.Name,
				zoneConf.RegexipEnabled,
				certmanEnable)
			pigdns.HandleMux(dns.Fqdn(zoneConf.Name), h, dnsMux, false)
			pigdns.HandleMux(dns.Fqdn(zoneConf.Name), h, dohMux, true)
		}

		if conf.NetListener.Enabled {
			s := server.NewServer(dnsMux, conf.NetListener.Address)
			wg.Add(1)
			go func() {
				s.Start()
				wg.Done()
			}()
		}

		// I need a zone conf to be able to use doh
		if conf.DOHEnabled && conf.Zone.Enabled {
			ws := web.NewWebServer(
				dohMux,
				conf.DataDir,
				conf.Zone.Name,
			)
			wg.Add(1)
			go func() {
				ws.Start()
				wg.Done()
			}()
		}

		go metrics.RunServer()

		wg.Wait()
	},
}

func main() {
	rootCmd.Execute()
}
