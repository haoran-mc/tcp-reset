package main

import (
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/haoran-mc/tcp-reset/config"
	_ "github.com/haoran-mc/tcp-reset/log"
	"github.com/haoran-mc/tcp-reset/packet"
	"github.com/haoran-mc/tcp-reset/util"
)

func main() {
	util.InitBlockIPs() // IP 黑名单

	handle, err := pcap.OpenLive(config.Conf.Nic, 9000, true, time.Microsecond)
	if err != nil {
		log.Fatalf("fail to listen mirror nic: %v", err)
	}
	defer handle.Close()

	// init send packet channel
	ch := make(chan gopacket.Packet)
	go packet.SendPacket(handle, ch)

	// capture live traffic
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range packetSource.Packets() {
		go packet.AnalysePacket(pkt, ch)
	}
}
