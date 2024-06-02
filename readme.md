# Port Scan
## 介绍
使用golang实现主机扫描和端口扫描功能，支持使用TCP和ICMP协议进行主机存活扫描和使用TCP连接、SYN半连接和UDP报文回显来扫描开放端口和关闭端口  
若干功能尚未实现（FIN扫描 UDP扫描）
## 依赖
```
go get github.com/google/gopacket
go get golang.org/x/net
```
## 参数配置
位于`./src/scan/tcpScan`中的ethName需要根据使用的网卡修改，具体方法可以使用pcap包中的FindAllDev()进行产看，该函数返回本机所有网卡的数据（网卡名、IP地址等）
## 用法
构建：
```
go build main.go
```
查看帮助：
```
./main -h
```
进行扫描：
```
./main -ip <IP地址> [-port <端口号>] -<协议>
```
上述协议可选-live（使用TCP扫描存活主机）、-icmp（使用icmp扫描存活主机、-t（使用TCP连接判断存活端口）、-sT（使用SYN半连接判断存活端口）、-sU（使用UDP判断关闭端口）
