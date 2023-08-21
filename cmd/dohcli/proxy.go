package main

import (
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
	viper.BindPFlag(ServerFlag, proxyCmd.Flags().Lookup(ServerAddrFlag))
}

var proxyCmd = &cobra.Command{
	Use:  "proxy",
	Long: "start a local dns proxy against the doh server",
	Run: func(cmd *cobra.Command, args []string) {
		dohServerName := viper.GetString(ServerFlag)
		dohSserverAddr := viper.GetString(ServerAddrFlag)

		if dohServerName == "" || dohSserverAddr == "" {
			cmd.Help()
			os.Exit(1)
		}

		pigdns.Handle(".", server.BuildDOHProxyHandler(dohServerName, dohSserverAddr))

		dnsServer := server.NewServer(dns.DefaultServeMux, ":53")
		dnsServer.Start()
	},
}
