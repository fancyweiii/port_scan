package packet

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"net"
	"testing"
)

func TestGetMACAddress(t *testing.T) {
	srcIP := net.ParseIP("10.31.220.220")
	desIP := net.ParseIP("10.31.220.224")

	// 这里使用WLAN网卡进行测试，具体可以更改，更改需要和arpPacket中的网卡信息一同更改
	handle, err := pcap.OpenLive("\\Device\\NPF_{B3997851-87D5-4CE8-8D87-320F6E89557B}", 1600, true, pcap.BlockForever)

	if err != nil {
		fmt.Println(err)
	}

	defer handle.Close()

	mac, err := GetMACAddress(handle, srcIP, desIP)

	fmt.Print("des MAC : ")
	fmt.Println(mac)
}

//func TestSendSYNPacket(t *testing.T) {
//	srcIP := "192.168.3.62"
//	dstIP := "192.168.3.58"
//	srcPort := 53734
//	dstPort := 139
//	handle, err := pcap.OpenLive("\\Device\\NPF_{B3997851-87D5-4CE8-8D87-320F6E89557B}", 1600, true, pcap.BlockForever)
//
//	if err != nil {
//		fmt.Println(err)
//	}
//	defer handle.Close()
//
//	dstMac, _ := GetMACAddress(handle, net.ParseIP(srcIP), net.ParseIP(dstIP))
//
//	err = SendSYNPacket(handle, net.ParseIP(srcIP), net.ParseIP(dstIP), srcPort, dstPort, dstMac)
//
//}
