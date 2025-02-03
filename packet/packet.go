package packet

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func SendResetPacket(handleMgt *pcap.Handle, c chan [2]gopacket.Packet) {
	for {
		packets := <-c
		if err := handleMgt.WritePacketData(packets[0].Data()); err != nil {
			fmt.Println("Send error", err.Error())
		}
		if err := handleMgt.WritePacketData(packets[1].Data()); err != nil {
			fmt.Println("Send error", err.Error())
		}
	}
}

func AnalysePacket(packet gopacket.Packet, handleMgt *pcap.Handle, c chan [2]gopacket.Packet) {
	// ipv4
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		// tcp
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			fmt.Println(ip, tcp)
		}
	}
}
