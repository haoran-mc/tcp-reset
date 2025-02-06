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
	// 黑白名单
	util.InitAllowDenyIPList()

	// 镜像网卡流量
	mirrorHandle, err := pcap.OpenLive(config.Conf.MirrorNic, 9000, true, time.Microsecond)
	if err != nil {
		log.Panicf("fail to listen mirror nic: %v", err)
	}
	defer mirrorHandle.Close()

	// 阻断网卡流量
	blockHandle, err := pcap.OpenLive(config.Conf.BlockNic, 9000, false, time.Microsecond)
	if err != nil {
		log.Panicf("fail to listen send nic: %v", err)
	}
	defer blockHandle.Close()

	// init send packet channel
	ch := make(chan gopacket.Packet)
	go packet.SendPacket(blockHandle, ch)

	// Capture Live Traffic
	packetSource := gopacket.NewPacketSource(mirrorHandle, mirrorHandle.LinkType())
	for pkt := range packetSource.Packets() {
		go packet.AnalysePacket(pkt, blockHandle, ch)
	}
}
