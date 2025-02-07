package util

import (
	"bufio"
	"log"
	"os"
	"strings"

	"github.com/haoran-mc/tcp-reset/config"
)

var blockIPs map[string]struct{}

func InitBlockIPs() {
	blockIPs = make(map[string]struct{})

	f, err := os.Open(config.Conf.BlockIPs)
	if err != nil {
		log.Fatalf("fail to open blacklisted file: %v", err)
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
		log.Fatalf("scanner scan error: %v", err)
	}
}

func InBlockIPs(ip string) bool {
	_, get := blockIPs[ip]
	return get
}
