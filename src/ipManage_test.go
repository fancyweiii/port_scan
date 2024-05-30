package src

import (
	"fmt"
	"testing"
)

func TestAliveDevice(t *testing.T) {
	ip := "10.31.220.220-10.31.220.240"
	ipa, _ := ParaConvert(ip, "")
	fmt.Println("Alive Device:")
	for _, v := range AliveDevice(ipa.addresses) {
		fmt.Println(v)
	}
}

func TestParaConvert(t *testing.T) {
	addresses := "1.1.1.1, 192.168.0.1-192.168.0.20, 172.16.10.3/24"
	ports := ""
	ipa, err := ParaConvert(addresses, ports)
	if err == nil {
		for _, v := range ipa.addresses {
			fmt.Println(v)
		}
		for _, v := range ipa.ports {
			fmt.Println(v)
		}
	}
}

func TestIPAddress_SelectTCP(t *testing.T) {
	ip := "172.20.10.1"
	port := ""
	ipa, _ := ParaConvert(ip, port)
	fmt.Print(ip)
	fmt.Println(" opened port:")
	ports, err := ipa.SelectTCP(2)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, port := range ports {
		fmt.Println(port)
	}
}

func TestIPAddress_SelectUDP(t *testing.T) {
	ip := "192.168.3.66"
	port := "53"
	ipa, _ := ParaConvert(ip, port)
	fmt.Print(ip)
	fmt.Println(" opened port:")
	ports, err := ipa.SelectUDP(1)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, port := range ports {
		fmt.Println(port)
	}
}
