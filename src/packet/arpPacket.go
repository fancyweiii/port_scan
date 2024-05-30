package packet

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
)

func GetLocalMac() (net.HardwareAddr, error) {
	// 获取当前网卡信息
	eInterface, err := net.Interfaces()

	for _, v := range eInterface {
		if v.Name == "WLAN" {
			return v.HardwareAddr, err
		}
	}

	return nil, err
}

func GetLocalIP(name string) (ip net.IP) {
	eInter, _ := pcap.FindAllDevs()
	for _, v := range eInter {
		if v.Name == name {
			return v.Addresses[0].IP
		}
	}
	return nil
}

func GetMACAddress(handle *pcap.Handle, srcIP, dstIP net.IP) (net.HardwareAddr, error) {
	//获取本地地址
	localMac, _ := GetLocalMac()

	// 创建以太网层
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       localMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	// 创建ARP报文
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(localMac),
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      make([]byte, 6),
		DstProtAddress:    dstIP.To4(),
	}

	// 创建序列化缓冲区
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	// 序列化数据包
	err := gopacket.SerializeLayers(buffer, options, ethernetLayer, arpLayer)
	if err != nil {
		return nil, err
	}

	// 发送ARP请求数据包
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	// 捕获ARP响应
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(5 * time.Second)
	for {
		select {
		case packet := <-packetSource.Packets():
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer != nil {
				arp, _ := arpLayer.(*layers.ARP)
				if net.IP(arp.SourceProtAddress).Equal(dstIP) {
					return net.HardwareAddr(arp.SourceHwAddress), nil
				}
			}
		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for ARP reply")
		}
	}
}
