package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/ferama/pigdns/pkg/doh"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	mainCmd.AddCommand(qCmd)
}

var qCmd = &cobra.Command{
	Use:  "q",
	Long: "query doh server",
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		server := viper.GetString(ServerFlag)
		serverAddr := fmt.Sprintf("https://%s", server)

		if server == "" {
			cmd.Help()
			os.Exit(1)
		}
		query := args[0]
		qtype := dns.TypeA
		if len(args) > 1 {
			recordType := strings.ToUpper(args[1])
			qtype = dns.StringToType[recordType]
		}

		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(query), qtype)
		req, err := doh.NewRequest("POST", serverAddr, m)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		respMsg, err := doh.ResponseToMsg(res)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Print(respMsg)

	},
}
