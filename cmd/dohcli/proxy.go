package main

import (
	"fmt"
	"net"
	"os"

	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/server"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	mainCmd.AddCommand(proxyCmd)

	proxyCmd.Flags().StringP(ServerAddrFlag, "a", "", "the https doh server ip address")
	viper.BindPFlag(ServerAddrFlag, proxyCmd.Flags().Lookup(ServerAddrFlag))
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start a local dns proxy against a doh server",
	Long:  "Start a local dns proxy against a doh server",
	Run: func(cmd *cobra.Command, args []string) {
		dohServerName := viper.GetString(ServerNameFlag)
		dohServerAddr := viper.GetString(ServerAddrFlag)

		if dohServerName == "" {
			cmd.Help()
			os.Exit(1)
		}

		if dohServerAddr == "" {
			ips, err := net.LookupIP(dohServerName)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			dohServerAddr = ips[0].String()
		}

		pigdns.Handle(".", server.BuildDOHProxyHandler(dohServerName, dohServerAddr))

		dnsServer := server.NewServer(dns.DefaultServeMux, ":53")
		dnsServer.Start()
	},
}
