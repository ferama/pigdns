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

const (
	ServerFlag = "server"
)

func init() {
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)

	viper.AutomaticEnv()
	viper.SetEnvPrefix("doh")

	rootCmd.Flags().StringP(ServerFlag, "s", "", "the https doh server")
	viper.BindPFlag(ServerFlag, rootCmd.Flags().Lookup(ServerFlag))
}

var rootCmd = &cobra.Command{
	Use:  "doh",
	Long: "query doh server",
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		server := viper.GetString(ServerFlag)

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
		req, err := doh.NewRequest("POST", server, m)
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

func main() {
	rootCmd.Execute()
}
