package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ferama/pigdns/pkg/doh"
	"github.com/ferama/pigdns/pkg/pigdns"
	"github.com/ferama/pigdns/pkg/server"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	mainCmd.AddCommand(proxyCmd)

	proxyCmd.Flags().StringP(ServerAddrFlag, "a", "", "the https doh server ip address")
	viper.BindPFlag(ServerFlag, proxyCmd.Flags().Lookup(ServerAddrFlag))
}

func buildProxy(server string, serverAddr string) pigdns.HandlerFunc {
	return func(ctx context.Context, r *pigdns.Request) {

		serverHTTPAddr := fmt.Sprintf("https://%s", server)
		req, err := doh.NewRequest("POST", serverHTTPAddr, r.Msg)
		if err != nil {
			log.Err(err)
			return
		}

		dialer := &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 5 * time.Second,
		}

		http.DefaultTransport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			// force resolve doh server name to its ip
			if addr == fmt.Sprintf("%s:443", server) {
				addr = fmt.Sprintf("%s:443", serverAddr)
			}
			return dialer.DialContext(ctx, network, addr)
		}

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Err(err)
			return
		}
		respMsg, err := doh.ResponseToMsg(res)
		if err != nil {
			log.Err(err)
			return
		}
		r.Reply(respMsg)

		event := log.Info().
			Str("query", r.Name()).
			Str("type", r.Type()).
			Str("protocol", r.Proto())

		event.Send()
	}
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

		pigdns.Handle(".", buildProxy(dohServerName, dohSserverAddr))

		dnsServer := server.NewServer(dns.DefaultServeMux, ":53")
		dnsServer.Start()
	},
}
