package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	ServerNameFlag = "server-name"
	ServerAddrFlag = "server-addr"
)

func init() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)

	viper.AutomaticEnv()
	viper.SetEnvPrefix("doh")

	mainCmd.PersistentFlags().StringP(ServerNameFlag, "s", "", "the https doh server name (Ex. doh.example.net)")
	viper.BindPFlag(ServerNameFlag, mainCmd.PersistentFlags().Lookup(ServerNameFlag))
}

var mainCmd = &cobra.Command{
	Use:  "doh",
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("invalid subcommand")
		os.Exit(1)
	},
}

func main() {
	mainCmd.Execute()
}
