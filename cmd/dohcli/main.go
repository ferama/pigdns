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

	DebugFlag = "debug"
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

	mainCmd.PersistentFlags().Bool(DebugFlag, false, "enable debug")
	viper.BindPFlag(DebugFlag, mainCmd.PersistentFlags().Lookup(DebugFlag))
}

var mainCmd = &cobra.Command{
	Use:  "doh",
	Args: cobra.MinimumNArgs(1),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		debug := viper.GetBool(DebugFlag)

		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		if debug {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("invalid subcommand")
		os.Exit(1)
	},
}

func main() {
	mainCmd.Execute()
}
