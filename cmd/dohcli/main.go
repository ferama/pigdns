package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	ServerNameFlag = "server-name"
	ServerAddrFlag = "server-addr"

	DebugFlag = "debug"
)

func init() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	mainCmd.PersistentFlags().StringP(ServerNameFlag, "s", "", "the https doh server name (Ex. doh.example.net)")
	mainCmd.PersistentFlags().Bool(DebugFlag, false, "enable debug")
}

var mainCmd = &cobra.Command{
	Use:  "doh",
	Args: cobra.MinimumNArgs(1),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		debug, _ := cmd.Flags().GetBool(DebugFlag)

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
