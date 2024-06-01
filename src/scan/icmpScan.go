package scan

import (
	"net"
	"os"
	"time"
)

type ICMPipAdd struct {
	Addresses []string
}

const ICMP_ECHO_REQUEST = 8

type ICMPScan interface {
	IcmpAliveScan() ([]net.IP, error)
}

func ping(ip string, liChan chan string) {
	conn, err := net.Dial("ip4:icmp", ip)
	if err != nil {
		liChan <- "0.0.0.0"
		return
	}

	defer conn.Close()

	id := os.Getpid() & 0xffff
	seq := 1

	// 构造ICMP报文
	icmp := make([]byte, 8+32)
	icmp[0] = ICMP_ECHO_REQUEST
	icmp[1] = 0
	icmp[2] = 0
	icmp[3] = 0
	icmp[4] = byte(id >> 8)
	icmp[5] = byte(id & 0xff)
	icmp[6] = byte(seq >> 8)
	icmp[7] = byte(seq & 0xff)
	copy(icmp[8:], "abcdefghijklm") // Payload

	cs := checkSum(icmp)
	icmp[2] = byte(cs >> 8)
	icmp[3] = byte(cs & 0xff)

	_, err = conn.Write(icmp)
	if err != nil {
		liChan <- "0.0.0.0"
		return
	}

	// 设置超时
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	// 读取reply报文
	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	if err != nil {
		//fmt.Println(err)
		liChan <- "0.0.0.0"
		return
	}

	// 读取到返回报文，返回IP地址
	liChan <- ip
}

func (ipa *ICMPipAdd) IcmpAliveScan() ([]string, error) {
	var ret []string
	liveIP := make(chan string, len(ipa.Addresses))

	for _, ip := range ipa.Addresses {
		go ping(ip, liveIP)
	}

	chanLen := 0
	// 循环直至结束
	for {
		tempIP := <-liveIP
		// 判断是否为合法IP
		if tempIP != "0.0.0.0" {
			ret = append(ret, tempIP)
		}
		chanLen++
		if chanLen == len(ipa.Addresses) {
			break
		}
	}

	return ret, nil
}

// 计算校验和
func checkSum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(^sum)
}
