package packet

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

		}

func SendPacket(handle *pcap.Handle, ch chan gopacket.Packet) {
	for {
		packets := <-ch
		if err := handle.WritePacketData(packets.Data()); err != nil {
			fmt.Println("Send error", err.Error())
		}
	}
}

func AnalysePacket(packet gopacket.Packet, handleMgt *pcap.Handle, ch chan gopacket.Packet) {
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
