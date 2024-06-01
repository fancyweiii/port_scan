package scan

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"net"
	"port_scan/src/packet"
	"strconv"
	"time"
)

type TCPipAdd struct {
	Addresses []string
	Ports     []int
}

var srcMac net.HardwareAddr
var srcIPAdd net.IP
var ethName = "\\Device\\NPF_{B3997851-87D5-4CE8-8D87-320F6E89557B}"

type TCPScan interface {
	TCPConnect() ([]int, error)
	StealthScan() ([]int, error)
	FinScan() ([]int, error)
}

func openedTCPConn(ip string, port int, liChan chan int) {
	conn, err := net.DialTimeout("tcp", ip+":"+strconv.Itoa(port), time.Millisecond*200)
	if err == nil {
		liChan <- port
		conn.Close()
		return
	}
	// 没有建立连接将0加入通道  后续处理结果时过滤掉0
	liChan <- 0
}

// TCP连接扫描
func (ipa *TCPipAdd) TCPConnect() ([]int, error) {
	if len(ipa.Addresses) > 1 {
		return nil, fmt.Errorf("TOO MANY IP!  MULTI-THREAD ONLY SUPPORT PORTS!  ONLY ONE IP SUPPORT!")
	}
	var ret []int
	ip := ipa.Addresses[0]
	if ipa.Ports == nil {
		maxLen := 1000
		tempLen := 0
		liveChan := make(chan int, maxLen)
		for port := 1; port < 1001; port++ {
			go openedTCPConn(ip, port, liveChan)
		}
		for {
			tempPort := <-liveChan
			tempLen++
			if tempPort != 0 {
				ret = append(ret, tempPort)
			}
			if tempLen == maxLen {
				close(liveChan)
				break
			}
		}
	} else {
		maxLen := len(ipa.Ports)
		tempLen := 0
		liveChan := make(chan int, maxLen)
		for _, port := range ipa.Ports {
			go openedTCPConn(ip, port, liveChan)
		}
		for {
			tempPort := <-liveChan
			tempLen++
			if tempPort != 0 {
				ret = append(ret, tempPort)
			}
			if tempLen == maxLen {
				close(liveChan)
				break
			}
		}
	}
	return ret, nil
}

func openedSYN(dstIP net.IP, srcPort, dstPort int, dstMAC net.HardwareAddr, liChan chan int) {
	// device需要根据网卡具体获取（pcap.FindAllDev()）
	handle, err := pcap.OpenLive(ethName, 1600, true, pcap.BlockForever)

	defer handle.Close()

	if err != nil {
		fmt.Println(err)
	}

	err = packet.SendSYNPacket(handle, srcIPAdd, dstIP, srcPort, dstPort, srcMac, dstMAC)

	if err != nil {
		fmt.Println(err)
	}

	if ok, _ := packet.CatchTCPPacket(handle, srcPort); ok {
		liChan <- dstPort
		return
	}

	liChan <- 0
}

// SYN扫描
func (ipa *TCPipAdd) StealthScan() ([]int, error) {
	handle, err := pcap.OpenLive(ethName, 1600, true, pcap.BlockForever)

	if err != nil {
		fmt.Println(err)
	}

	if len(ipa.Addresses) > 1 {
		return nil, fmt.Errorf("TOO MANY IP!  MULTI-THREAD ONLY SUPPORT PORTS!  ONLY ONE IP SUPPORT!")
	}
	var ret []int
	ip := ipa.Addresses[0]
	srcMac, _ = packet.GetLocalMac()
	srcIPAdd = packet.GetLocalIP(ethName)
	dstMAC, _ := packet.GetMACAddress(handle, srcIPAdd, net.ParseIP(ip))

	handle.Close()

	if ipa.Ports == nil {
		maxLen := 1000
		tempLen := 0
		liveChan := make(chan int, maxLen)
		for port := 1; port < 1001; port++ {
			go openedSYN(net.ParseIP(ip), (40000+port)%65535, port, dstMAC, liveChan)
		}
		for {
			tempPort := <-liveChan
			tempLen++
			if tempPort != 0 {
				ret = append(ret, tempPort)
			}
			if tempLen == maxLen {
				close(liveChan)
				break
			}
		}
	} else {
		maxLen := len(ipa.Ports)
		tempLen := 0
		liveChan := make(chan int, maxLen)
		for _, port := range ipa.Ports {
			go openedSYN(net.ParseIP(ip), (40000+port)%65535, port, dstMAC, liveChan)
		}
		for {
			tempPort := <-liveChan
			tempLen++
			if tempPort != 0 {
				ret = append(ret, tempPort)
			}
			if tempLen == maxLen {
				close(liveChan)
				break
			}
		}
	}

	return ret, nil
}

//func (ipa *TCPipAdd) FinScan() ([]int, error) {
//	//--------------------------------------------------------------------------------
//	if len(ipa.Addresses) > 1 {
//		return nil, fmt.Errorf("TOO MANY IP!  MULTI-THREAD ONLY SUPPORT PORTS!  ONLY ONE IP SUPPORT!")
//	}
//	var ret []int
//
//	return ret, nil
//}
