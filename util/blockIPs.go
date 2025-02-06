package util

import (
	"bufio"
	"os"
	"strings"

	"github.com/haoran-mc/tcp-reset/config"
)

var blockIPs map[string]struct{}

func InitBlockIPs() {
	blockIPs = make(map[string]struct{})

	f, err := os.Open(config.Conf.blockIPs)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if len(ip) == 0 {
			continue
		}
		blockIPs[ip] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
}

func InBlockIPs(ip string) bool {
	_, get := blockIPs[ip]
	return get
}
