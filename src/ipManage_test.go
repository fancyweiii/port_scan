package src

import (
	"fmt"
	"testing"
)

func TestAliveDevice(t *testing.T) {
	ip := "10.31.220.220-10.31.220.240"
	ipa, _ := ParaConvert(ip, "")
	fmt.Println("Alive Devices:")
	for _, v := range AliveDevice(ipa.Addresses) {
		fmt.Println(v)
	}
}

func TestParaConvert(t *testing.T) {
	addresses := "1.1.1.1, 192.168.0.1-192.168.0.20, 172.16.10.3/24"
	ports := ""
	ipa, err := ParaConvert(addresses, ports)
	if err == nil {
		for _, v := range ipa.Addresses {
			fmt.Println(v)
		}
		for _, v := range ipa.Ports {
			fmt.Println(v)
		}
	}
}

func TestIPAddress_SelectTCP(t *testing.T) {
	ip := "10.31.0.1"
	port := ""
	ipa, _ := ParaConvert(ip, port)
	fmt.Print(ip)
	fmt.Println(" opened Ports:")
	ports, err := ipa.SelectTCP(1)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, port := range ports {
		fmt.Println(port)
	}
}

func TestIPAddress_SelectUDP(t *testing.T) {
	ip := "10.31.0.1"
	port := ""
	ipa, _ := ParaConvert(ip, port)
	fmt.Println("UDP扫描只能确定关闭的端口 不能确定被过滤报文的情况")
	fmt.Print(ip)
	fmt.Print(" number of closed Ports: ")
	ports, err := ipa.SelectUDP(1)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(len(ports))
}

func TestIPAddress_SelectICMP(t *testing.T) {
	ip := "10.31.220.1/24"
	port := ""
	ipa, _ := ParaConvert(ip, port)
	fmt.Print(ip)
	fmt.Println(" alive hosts:")
	IPs, err := ipa.SelectICMP(1)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, ip := range IPs {
		fmt.Println(ip)
	}
}
