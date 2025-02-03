package config

import (
	"log"
	"os"

	"github.com/BurntSushi/toml"
)

type tomlConfig struct {
	LogLevel  string `toml:"log-level"`
	MirrorNic string `toml:"mirror-nic"`
	BlockNic  string `toml:"block-nic"`
	IPs       string `toml:"ip-list"`
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
