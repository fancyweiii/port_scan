package scan

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
)



//----------------------------------------Failed to scan-----------------------------------------------------

type UDPipADD struct {
	Addresses []string
	Ports     []int
}

type UDPScan interface {
	UdpScanPort() ([]int, error)
}

func udpScanMul(dIP string, port int) {
	addr := net.UDPAddr{
		IP:   net.ParseIP(dIP).To4(),
		Port: port,
	}

	// udp连接
	conn, err := net.DialUDP("udp", nil, &addr)

	if err != nil {
		fmt.Println(err)
		return
	}

	defer conn.Close()

	// 发送空udp数据包
	_, err = conn.Write([]byte(" "))

	if err != nil {
		fmt.Println(err)
		//return
	}
}

// 选哟一个额外的线程来抓获ICMP报文来分析被拒绝的报文
func catchICMP(startTime int64, clChan chan int) {

	handle, err := pcap.OpenLive(ethName, 1600, false, pcap.BlockForever)

	if err != nil {
		fmt.Println(err)
		return
	}

	defer handle.Close()
	// 设置只过滤icmp报文
	handle.SetBPFFilter("icmp")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	time.Sleep(time.Second * 2)
	for pac := range packetSource.Packets() {
		//对icmp报文进行解析
		ipLayer := pac.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			innerPacket := gopacket.NewPacket(ip.Payload, layers.LayerTypeICMPv4, gopacket.Default)
			udpLayer := innerPacket.Data()
			port := int(binary.BigEndian.Uint16(udpLayer[30:32]))
			clChan <- port
		}

		//if time.Now().Unix()-startTime >= 5 {
		//	return
		//}

	}
}

func (ipa *UDPipADD) UdpScanPort() ([]int, error) {
	if len(ipa.Addresses) > 1 {
		return nil, fmt.Errorf("TOO MANY IP!  MULTI-THREAD ONLY SUPPORT PORTS!  ONLY ONE IP SUPPORT!")
	}

	dstIP := ipa.Addresses[0]
	var ret []int

	startTime := time.Now().Unix()

	chLen := len(ipa.Ports)
	if chLen == 0 {
		chLen = 1000
	}
	closeChan := make(chan int, chLen)
	go catchICMP(startTime, closeChan)

	if ipa.Ports == nil {

		for port := 1; port < 1001; port++ {
			go udpScanMul(dstIP, port)
		}
	} else {
		for _, port := range ipa.Ports {
			go udpScanMul(dstIP, port)
		}
	}

overloop:
	for {
		select {
		case val := <-closeChan:
			if val != 0 {
				ret = append(ret, val)
			}
		case <-time.After(5 * time.Second):
			break overloop
		}
	}

	close(closeChan)

	return ret, nil
}
