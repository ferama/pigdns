package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/racer"
	"github.com/ferama/pigdns/pkg/recursor"
	"github.com/ferama/pigdns/pkg/server"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	mainCmd.AddCommand(proxyCmd)

	proxyCmd.Flags().StringP(ServerAddrFlag, "a", "", "the https doh server ip address")
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start a local dns proxy against a doh server",
	Long:  "Start a local dns proxy against a doh server",
	Example: `
  doh proxy -s doh.yourpidns.com	
	`,
	Run: func(cmd *cobra.Command, args []string) {
		dohServerName, _ := cmd.Flags().GetString(ServerNameFlag)
		dohServerAddr, _ := cmd.Flags().GetString(ServerAddrFlag)

		if dohServerName == "" {
			cmd.Help()
			os.Exit(1)
		}

		if dohServerAddr == "" {
			qr := racer.NewQueryRacer(os.TempDir(), 1024*100)
			r := recursor.New("", 0, qr)
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(dohServerName), dns.TypeA)

			resp, err := r.Query(context.Background(), m, false)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			rset := utils.MsgExtractByType(resp, dns.TypeA, "")
			if len(rset) == 0 {
				fmt.Println("cannot resolve server name")
				os.Exit(1)
			}
			ans := rset[0]
			ra, _ := ans.(*dns.A)
			dohServerAddr = ra.A.String()
			log.Info().Msgf("%s resolved to %s", dohServerName, dohServerAddr)
		}

		pigdns.Handle(".", server.BuildDOHProxyHandler(dohServerName, dohServerAddr))

		dnsServer := server.NewServer(dns.DefaultServeMux, ":53")
		dnsServer.Start()
	},
}
