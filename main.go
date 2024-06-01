package main

import (
	"flag"
	"fmt"
	"port_scan/src"
)

func main() {
	ip := flag.String("ip", "", "IP地址")
	ports := flag.String("port", "", "端口号")
	live := flag.Bool("live", false, "存活扫描")
	t := flag.Bool("t", false, "使用TCP连接进行扫描")
	sT := flag.Bool("sT", false, "使用SYN半连接进行扫描")
	sU := flag.Bool("sU", false, "使用UDP扫描")
	icmp := flag.Bool("icmp", false, "使用ICMP扫描存活")
	help := flag.Bool("h", false, "帮助")

	flag.Parse()

	if (*ip == "" && *ports == "") || *help {
		fmt.Println("-ip IP地址 例：192.168.0.1, 192.168.1.1/24, 192.168.1.2-192.168.1.10")
		fmt.Println("-port 端口号 例：19, 19-190")
		fmt.Println("-port 端口号 例：19, 19-190")
		fmt.Println("-live 使用TCP扫描存活主机")
		fmt.Println("-icmp 使用ICMP扫描存活主机")
		fmt.Println("-t 使用TCP扫描存活端口")
		fmt.Println("-sT 使用SYN半连接扫描存活端口")
		fmt.Println("-sU 使用UDP扫描关闭端口")
	}

	if !(*live || *t || *sT || *sU || *icmp) {
		fmt.Println("使用-h查看帮助")
	}

	// 参数转换
	ipa, _ := src.ParaConvert(*ip, *ports)

	if *live {
		fmt.Println("Alive Devices:")
		for _, v := range src.AliveDevice(ipa.Addresses) {
			fmt.Println(v)
		}
	} else if *icmp {
		fmt.Println("Alive hosts:")
		IPs, err := ipa.SelectICMP(1)
		if err != nil {
			fmt.Println(err)
			return
		}
		for _, ip := range IPs {
			fmt.Println(ip)
		}
	} else if *t || *sT {
		fmt.Print(ip)
		fmt.Println(" opened Ports:")
		var ports []int
		var err error
		if *t {
			ports, err = ipa.SelectTCP(1)
		} else {
			ports, err = ipa.SelectTCP(2)
		}
		if err != nil {
			fmt.Println(err)
			return
		}
		for _, port := range ports {
			fmt.Println(port)
		}
	} else if *sU {
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
}
