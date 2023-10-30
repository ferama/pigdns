package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
	"github.com/rs/zerolog/log"
)

type zone struct {
	Enabled bool `koanf:"enabled"`

	Name           string `koanf:"name"`
	RegexipEnabled bool   `koanf:"regexipEnabled"`

	ZoneFilePath string `koanf:"zoneFilePath"`
}

type certm struct {
	Enabled    bool   `koanf:"enabled"`
	UseStaging bool   `koanf:"useStaging"`
	Email      string `koanf:"email"`
}

// this struct holds the net listener configuration.
type netListener struct {
	// You can disable the standard net listener.
	// You may want to enable the DOH mode only
	Enabled bool `koanf:"enabled"`
	// the address here, referes to both tcp and udp protocols
	Address string `koanf:"address"`
}

type recursorConf struct {
	Enabled     bool     `koanf:"enabled"`
	AllowedNets []string `koanf:"allowedNets"`
	ServeOnUDP  bool     `koanf:"serveOnUDP"`
	BlockLists  []string `koanf:"blockLists"`
	WhiteLists  []string `koanf:"whiteLists"`
	CacheSize   int      `koanf:"cacheSize"`
}
type conf struct {
	LogLevel string `koanf:"logLevel"`
	DataDir  string `koanf:"dataDir"`

	NetListener netListener `koanf:"netListener"`
	DOHEnabled  bool        `koanf:"dohEnabled"`

	Recursor recursorConf `koanf:"recursor"`

	Zone    zone  `koanf:"zone"`
	Certman certm `koanf:"certman"`
}

func (c *conf) pprint() {
	pp, err := json.MarshalIndent(c, "", "  ")
	log.Print("=== Current conf ===")
	if err == nil {
		log.Printf("\n%s", pp)
	}
	log.Print("===  ===")
}

func loadConf(path string) *conf {
	var k = koanf.New(".")

	// default values
	k.Load(structs.Provider(conf{
		LogLevel: "info",
		DataDir:  ".",
		NetListener: netListener{
			Enabled: true,
			Address: ":53",
		},
		DOHEnabled: false,
		Recursor: recursorConf{
			ServeOnUDP: false,
			AllowedNets: []string{
				"127.0.0.1/32",
				"::1",
			},
			CacheSize: 100000,
		},

		Certman: certm{
			Enabled:    false,
			UseStaging: false,
			Email:      "user@not-exists.com",
		},
	}, "."), nil)

	// merge with config file
	err := k.Load(file.Provider(path), yaml.Parser())
	if err != nil {
		fmt.Printf("error while parsing conf file at '%s'\n", path)
		os.Exit(1)
	}

	// allow overrides from env
	// Ex: PIGDNS_netListener_address=":5353"
	k.Load(env.Provider("PIGDNS_", ".", func(s string) string {
		return strings.Replace(strings.TrimPrefix(s, "PIGDNS_"), "_", ".", -1)
	}), nil)

	var c conf
	k.Unmarshal("", &c)

	return &c
}
