package util

import (
	"bufio"
	"os"
	"strings"
)

const (
	WHITE = 0 // 白名单
	BLACK = 1 // 黑名单
)

// IP: WHITE, IP: BLACK
var AllowDenyIPs map[string]uint8

func InitAllowDenyIPList() {
	AllowDenyIPs = make(map[string]uint8)

	// Read black IPs
	readIPsFromFile("res/black-ips.txt", BLACK)

	// Read white IPs
	readIPsFromFile("res/white-ips.txt", WHITE)
}

func readIPsFromFile(filePath string, listType uint8) {
	f, err := os.Open(filePath)
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
		AllowDenyIPs[ip] = listType
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
}

func MatchIP(ip string, matchType uint8) bool {
	return AllowDenyIPs[ip] == matchType
}
