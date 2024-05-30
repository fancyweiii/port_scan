package packet

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

// 发送SYN置位的TCP报文
func SendSYNPacket(handle *pcap.Handle, srcIP, dstIP net.IP, srcPort, dstPort int, localMac, dstMac net.HardwareAddr) error {
	// 创建IP层
	ipLayer := &layers.IPv4{
		Version:  4,
		SrcIP:    srcIP.To4(),
		DstIP:    dstIP.To4(),
		Protocol: layers.IPProtocolTCP,
	}

	// 创建TCP层
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
		Seq:     1105024978,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	//localMac, _ := GetLocalMac()

	// 创建以太网层
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       localMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// 创建序列化缓冲区
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// 序列化数据包
	err := gopacket.SerializeLayers(buffer, options, ethernetLayer, ipLayer, tcpLayer)
	if err != nil {
		return err
	}

	// 发送数据包
	return handle.WritePacketData(buffer.Bytes())
}

// 捕获TCP报文查看是否为ACK或者RST
func CatchTCPPacket(handle *pcap.Handle, srcPort, dstPort int) (bool, error) {
	packets := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packets.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.DstPort == layers.TCPPort(srcPort) {
				if tcp.SYN && tcp.ACK {
					return true, nil
				} else if tcp.RST {
					return false, nil
				}
				break
			}
		}
	}
	return false, fmt.Errorf("DO NOT CATCH PACKET")
}
