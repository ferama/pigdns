package main

import (
	"fmt"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
)

type zone struct {
	Enabled bool `koanf:"enabled"`

	Name           string `koanf:"name"`
	RegexipEnabled bool   `koanf:"regexipEnabled"`

	ZoneFilePath string `koanf:"zoneFilePath"`
}

type middlewares struct {
	Recursor struct {
		Enabled     bool     `koanf:"enabled"`
		EnableOnUDP bool     `koanf:"enableOnUDP"`
		AllowedNets []string `koanf:"allowedNets"`
	} `koanf:"recursor"`

	Zone zone `koanf:"zone"`
}

type certm struct {
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
	DataDir  string `koanf:"dataDir"`

	UDPTCPEnabled       bool   `koanf:"udpTCPEnabled"`
	UDPTCPListenAddress string `koanf:"udpTCPListenAddress"`

	DOHEnabled bool `koanf:"dohEnabled"`

	Middlewares middlewares `koanf:"middlewares"`
	Certman     certm       `koanf:"certman"`
}

func loadConf(path string, debug bool) *conf {
	if debug {
		fmt.Println("=== Current Conf ===")
	}
	var k = koanf.New(".")

	// default values
	k.Load(structs.Provider(conf{
		LogLevel:            "info",
		DataDir:             ".",
		UDPTCPEnabled:       true,
		DOHEnabled:          false,
		UDPTCPListenAddress: ":53",

		Certman: certm{
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
