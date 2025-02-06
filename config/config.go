package config

import (
	"log"
	"os"

	"github.com/BurntSushi/toml"
)

type tomlConfig struct {
	LogLevel string `toml:"log-level"`
	Nic      string `toml:"nic"`
	BlockIPs string `toml:"block-ips"`
}

var Conf = new(tomlConfig)

func init() {
	f := "config.toml"
	if _, err := os.Stat(f); err != nil {
		log.Fatalln(0, err)
	}

	_, err := toml.DecodeFile(f, &Conf)
	if err != nil {
		log.Fatalln(2, err)
	}
}
