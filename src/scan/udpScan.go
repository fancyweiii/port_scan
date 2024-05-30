package scan

import (
	"fmt"
	"net"
	"time"
)

type UDPipADD struct {
	Addresses []string
	Ports     []int
}

type UDPScan interface {
	UdpScanPort() ([]int, error)
}

func udpScanMul(dIP string, port int, liChan chan int) {
	addr := net.UDPAddr{
		IP:   net.ParseIP(dIP).To4(),
		Port: port,
	}

	// udp连接
	conn, err := net.DialUDP("udp", nil, &addr)

	if err != nil {
		liChan <- 0
		return
	}

	defer conn.Close()

	// 发送空udp数据包
	_, err = conn.Write([]byte(" "))

	if err != nil {
		liChan <- 0
		return
	}

	conn.SetReadDeadline(time.Now().Add(time.Second * 20))

	//读取响应
	buffer := make([]byte, 1024)
	_, _, err = conn.ReadFromUDP(buffer)
	if err != nil {
		liChan <- 0
		return
	}

	liChan <- port
}

func (ipa *UDPipADD) UdpScanPort() ([]int, error) {
	if len(ipa.Addresses) > 1 {
		return nil, fmt.Errorf("TOO MANY IP!  MULTI-THREAD ONLY SUPPORT PORTS!  ONLY ONE IP SUPPORT!")
	}

	dstIP := ipa.Addresses[0]
	var ret []int

	if ipa.Ports == nil {
		maxLen := 1000
		tempLen := 0
		liveChan := make(chan int, maxLen)
		for port := 1; port < 1001; port++ {
			go udpScanMul(dstIP, port, liveChan)
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
			go udpScanMul(dstIP, port, liveChan)
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
