package src

import (
	"fmt"
	"math"
	"net"
	"port_scan/src/scan"
	"strconv"
	"strings"
	"time"
)

type IPAddress struct {
	addresses []string
	ports     []int
}

type ProtocolSelect interface {
	SelectTCP(function int) ([]int, error)
	SelectUDP(function int) ([]int, error)
	SelectICMP(function int) ([]int, error)
}

// 参数转换
func ParaConvert(ip string, ports string) (IPAddress, error) {
	var ret IPAddress
	var tempPort []string
	tempIP := strings.Split(ip, ",")
	if ports != "" {
		tempPort = strings.Split(ports, ",")
	}

	// 字符串形式IP地址转为数值
	ipToUint32 := func(ip string) uint32 {
		ipN := net.ParseIP(ip)
		ipN = ipN.To4()
		return uint32(ipN[0])<<24 | uint32(ipN[1])<<16 | uint32(ipN[2])<<8 | uint32(ipN[3])
	}

	// 数值IP地址转回字符串
	uint32ToIP := func(ipInt uint32) string {
		return net.IPv4(byte(ipInt>>24), byte(ipInt>>16), byte(ipInt>>8), byte(ipInt)).String()
	}

	for _, v := range tempIP {
		if strings.Contains(v, "-") {
			ti := strings.Split(v, "-")
			start := ipToUint32(strings.TrimSpace(ti[0]))
			end := ipToUint32(strings.TrimSpace(ti[1]))
			for i := start; i <= end; i++ {
				ret.addresses = append(ret.addresses, uint32ToIP(i))
			}
		} else if strings.Contains(v, "/") {
			_, ipWithMask, _ := net.ParseCIDR(strings.TrimSpace(v))
			// 判断子网掩码是否过小，过小的mask导致需要扫描的IP地址过多，运行时间变长
			// 只支持mask >= 24
			maskLen, _ := ipWithMask.Mask.Size()
			if maskLen >= 24 {
				startIP := ipWithMask.IP
				startIP = startIP.To4()
				uint32IP := uint32(startIP[0])<<24 | uint32(startIP[1])<<16 | uint32(startIP[2])<<8 | uint32(startIP[3])
				endIP := uint32IP + uint32(math.Pow(2, float64(32-maskLen)))
				for i := uint32IP; i < endIP; i++ {
					ret.addresses = append(ret.addresses, uint32ToIP(i))
				}
			} else {
				return ret, fmt.Errorf("IP MASK TOO LONG")
			}
		} else {
			ret.addresses = append(ret.addresses, v)
		}
	}

	for _, v := range tempPort {
		if strings.Contains(v, "-") {
			tp := strings.Split(v, "-")
			start, _ := strconv.Atoi(strings.TrimSpace(tp[0]))
			end, _ := strconv.Atoi(strings.TrimSpace(tp[1]))
			for i := start; i <= end; i++ {
				ret.ports = append(ret.ports, i)
			}
		} else {
			port, _ := strconv.Atoi(strings.TrimSpace(v))
			ret.ports = append(ret.ports, port)
		}
	}
	return ret, nil
}

func isAlive(ipPort string, liChan chan bool) {
	conn, err := net.DialTimeout("tcp", ipPort, time.Second)
	if err == nil {
		liChan <- true
		conn.Close()
		return
	}
	liChan <- false
}

// tcp连接判断存活主机
func AliveDevice(ips []string) []string {
	var ret []string
	var targetPort = []string{"21", "23", "80", "135", "139", "443", "445", "8080", "49152", "62078"}
	for _, ip := range ips {
		liveChan := make(chan bool, len(targetPort))
		var targetLen []bool
		var tag = false
		for _, port := range targetPort {
			// 向多个常用端口发起tcp连接，100ms超时继续下一个
			go isAlive(ip+":"+port, liveChan)
		}
		for {
			tempTag := <-liveChan
			tag = tag || tempTag
			targetLen = append(targetLen, tempTag)
			if len(targetLen) == len(targetPort) {
				// 通过通道的tag数等于原数组长说明线程全部执行完毕，关闭通道退出循环
				close(liveChan)
				break
			}
		}
		if tag {
			ret = append(ret, ip)
		}
	}
	return ret
}

func (ipa *IPAddress) SelectTCP(function int) ([]int, error) {
	var tia scan.TCPipAdd
	tia.Addresses = ipa.addresses
	tia.Ports = ipa.ports
	switch function {
	case 1:
		return tia.TCPConnect()
	case 2:
		return tia.StealthScan()
	case 3:
		return tia.FinScan()
	default:
		return nil, fmt.Errorf("error para")
	}
}

func (ipa *IPAddress) SelectUDP(function int) ([]int, error) {
	var uia scan.UDPipADD
	uia.Addresses = ipa.addresses
	uia.Ports = ipa.ports
	switch function {
	case 1:
		return uia.UdpScanPort()

	default:
		return nil, fmt.Errorf("error para")
	}
}

func (ipa *IPAddress) SelectICMP(function int) ([]int, error) {
	//---------------------------------------------
	switch function {

	default:
		return nil, fmt.Errorf("error para")
	}
}
