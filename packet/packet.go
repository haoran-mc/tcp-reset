package packet

import (
	"fmt"
	"log/slog"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/haoran-mc/tcp-reset/util"
)

func forgePacket(packet gopacket.Packet) gopacket.Packet {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	eth, _ := ethLayer.(*layers.Ethernet)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)

	if tcp.RST || tcp.FIN {
		return nil
	}

	{ // tcp flags
		tcp.URG = false
		tcp.PSH = false
		tcp.FIN = false
		tcp.ECE = false
		tcp.CWR = false
		tcp.NS = false

		switch {
		case tcp.SYN && !tcp.ACK: // 一次握手，客户端发送 SYN 请求建立连接
			tcp.RST = false
			tcp.SYN = true
			tcp.ACK = true
			tcp.Ack = tcp.Seq + uint32(len(packet.Data()))
			tcp.Seq = 0

		case tcp.SYN && tcp.ACK: // 二次握手，服务端接受连接
			// do nothing
			return nil

		case tcp.ACK && tcp.PSH: // 建立连接后，通信过程中的标志位（TODO 考虑 !tcp.PSH 的情况）
			tcp.SYN = false
			tcp.RST = true
			tcp.ACK = false
			tcp.Ack = 0
			tcp.Seq = tcp.Ack

		default:
			slog.Info(fmt.Sprintf("No process is performed on traffic packets in the state of these flags:\n"+
				"URG:%t ACK:%t PSH:%t RST:%t SYN:%t FIN:%t ECE:%t CWR:%t NS:%t\n",
				tcp.URG, tcp.ACK, tcp.PSH, tcp.RST, tcp.SYN, tcp.FIN, tcp.ECE, tcp.CWR, tcp.NS))
			return nil
		}
	}

	tcp.Window = 0
	tcp.Urgent = 0
	tcp.Options = tcp.Options[:0]
	tcp.Payload = tcp.Payload[:0]

	tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
	ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
	eth.SrcMAC, eth.DstMAC = eth.DstMAC, eth.SrcMAC

	tcp.SetNetworkLayerForChecksum(ip)

	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	packetBuffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializePacket(packetBuffer, options, packet); err != nil {
		slog.Error("failed serialize packet", "error", err.Error())
		return nil
	}
	pkt := gopacket.NewPacket(packetBuffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return pkt
}

func SendPacket(handle *pcap.Handle, ch chan gopacket.Packet) {
	for {
		packets := <-ch
		if err := handle.WritePacketData(packets.Data()); err != nil {
			fmt.Println("Send error", err.Error())
		}
	}
}

func AnalysePacket(packet gopacket.Packet, ch chan gopacket.Packet) {
	// ipv4
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		// 黑名单
		if util.InBlockIPs(ip.SrcIP.String()) || util.InBlockIPs(ip.DstIP.String()) {
			fakePacket := forgePacket(packet)
			if fakePacket != nil {
				ch <- fakePacket
			}
		}
	}
}
