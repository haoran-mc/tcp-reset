package packet

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/haoran-mc/tcp-reset/util"
)

func forgePacket(packet gopacket.Packet) (retPkt gopacket.Packet, logMsg string) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	eth, _ := ethLayer.(*layers.Ethernet)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)

	if tcp.RST || tcp.FIN {
		return nil, "[Info] RST or FIN packet"
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
			logMsg = fmt.Sprintf("[First handshake] TCP Sequence number: %d, Packet length: %d, Forge packet Ack: %d", tcp.Seq, uint32(len(packet.Data())), tcp.Ack)
			tcp.Seq = 0

		case tcp.SYN && tcp.ACK: // 二次握手，服务端接受连接
			// do nothing
			logMsg = "[Second handshake] Do nothing"
			return nil, logMsg

		case tcp.ACK && tcp.PSH: // 建立连接后，通信过程中的标志位（TODO 考虑 !tcp.PSH 的情况）
			tcp.SYN = false
			tcp.RST = true
			tcp.ACK = false
			tcp.Ack = 0
			logMsg = fmt.Sprintf("[Connection establishment] TCP Sequence number: %d, Forge packet Ack: %d, Forge packet Seq: %d", tcp.Seq, 0, 0)
			tcp.Seq = tcp.Ack

		default:
			return nil, fmt.Sprintf("[Info] No processing is done on traffic packets in this state: "+
				"URG:%t ACK:%t PSH:%t RST:%t SYN:%t FIN:%t ECE:%t CWR:%t NS:%t",
				tcp.URG, tcp.ACK, tcp.PSH, tcp.RST, tcp.SYN, tcp.FIN, tcp.ECE, tcp.CWR, tcp.NS)
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
		slog.Error("failed to serialize packet", "error", err.Error())
		return nil, logMsg
	}
	retPkt = gopacket.NewPacket(packetBuffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return
}

func SendPacket(handle *pcap.Handle, ch chan gopacket.Packet) {
	for {
		pkt := <-ch
		if err := handle.WritePacketData(pkt.Data()); err != nil {
			slog.Error("fail to send packet", "error", err.Error())
		}
	}
}

func AnalysePacket(packet gopacket.Packet, ch chan gopacket.Packet) {
	// eth
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)

		// ipv4
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			// tcp
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				// 黑名单
				if util.InBlockIPs(ip.SrcIP.String()) || util.InBlockIPs(ip.DstIP.String()) {
					fakePacket, logMsg := forgePacket(packet)
					if fakePacket != nil {
						ch <- fakePacket
					}

					fmt.Println("[" + time.Now().Format(time.RFC3339) + "]" + " Received a piece of traffic from blacklist:" +
						fmt.Sprintf("\n\t[Ethernet Layer] Ethernet type: %s, MAC From %s to %s", eth.EthernetType.String(), eth.SrcMAC.String(), eth.DstMAC.String()) +
						fmt.Sprintf("\n\t[IPv4 Layer] Protocol: %s, IP From %s to %s", ip.Protocol.String(), ip.SrcIP.String(), ip.DstIP.String()) +
						fmt.Sprintf("\n\t[TCP Layer] From port %d to %d", tcp.SrcPort, tcp.DstPort) +
						"\n\t" + logMsg)
				}
			}
		}
	}
}
