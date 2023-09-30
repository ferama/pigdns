package main

import (
	"fmt"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
)

type middlewares struct {
	RegexipEnabled bool `koanf:"regexipEnabled"`
	Recursor       struct {
		Enabled     bool     `koanf:"enabled"`
		AllowedNets []string `koanf:"allowedNets"`
	} `koanf:"recursor"`
	ZoneFile struct {
		Enabled bool   `koanf:"enabled"`
		Path    string `koanf:"path"`
	} `koanf:"zoneFile"`
}

type UDPTCPDnsChain struct {
	Enabled       bool        `koanf:"enabled"`
	ListenAddress string      `koanf:"listenAddress"`
	Middlewares   middlewares `koanf:"middlewares"`
}

type DohChain struct {
	Enabled       bool        `koanf:"enabled"`
	ListenAddress string      `koanf:"listenAddress"`
	Middlewares   middlewares `koanf:"middlewares"`
}

type Certman struct {
	Enabled    bool   `koanf:"enabled"`
	UseStaging bool   `koanf:"useStaging"`
	Email      string `koanf:"email"`
	WebCerts   struct {
		Enabled bool   `koanf:"enabled"`
		ApiKey  string `koanf:"string"`
	} `koanf:"webCerts"`
}

type conf struct {
	LogLevel string `koanf:"logLevel"`
	Domain   string `koanf:"domain"`
	DataDir  string `koanf:"dataDir"`

	DohChain       DohChain       `koanf:"DOHChain"`
	UDPTCPDnsChain UDPTCPDnsChain `koanf:"UDPTCPDNSChain"`
	Certman        Certman        `koanf:"certman"`
}

func loadConf(path string, debug bool) *conf {
	if debug {
		fmt.Println("=== Current Conf ===")
	}
	var k = koanf.New(".")

	// default values
	k.Load(structs.Provider(conf{
		LogLevel: "info",
		DataDir:  ".",
		UDPTCPDnsChain: UDPTCPDnsChain{
			ListenAddress: ":53",
		},
		Certman: Certman{
			Enabled:    false,
			UseStaging: false,
			Email:      "user@not-exists.com",
		},
	}, "."), nil)

	k.Load(file.Provider(path), yaml.Parser())

	var c conf
	k.Unmarshal("", &c)

	if debug {
		k.Print()
	}
	return &c
}
