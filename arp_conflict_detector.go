package main

import (
    "bufio"
    "fmt"
    "log"
    "os"
    "net"
    "io"
    "time"
    "strconv"
    "strings"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

var (
    snapshotLen int32 = 1024
    promiscuous bool  = false
    err         error
    timeout     time.Duration = 30 * time.Second
    handle      *pcap.Handle

    ipMap  = make(map[string]string)
    macMap = make(map[string]string)

    logEnabled bool = true
    logger *log.Logger
)

func main() {
    // 创建日志文件
    logFile, err := os.OpenFile("log.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatal(err)
    }
    defer logFile.Close()

    // 创建一个新的日志记录器
    logger = log.New(io.MultiWriter(os.Stdout, logFile), "", log.LstdFlags)

    // 设置输出编码为UTF-8
    logger.SetPrefix("\xEF\xBB\xBF")

    // 获取所有网络接口
    devices, err := pcap.FindAllDevs()
    if err != nil {
        logger.Fatal(err)
    }

    // 打印网卡信息
    fmt.Println("Available network interfaces:")
    for i, device := range devices {
        fmt.Printf("%d. %s\n", i+1, device.Name)
        fmt.Printf("   Description: %s\n", device.Description)
        fmt.Printf("   Flags: %s\n", device.Flags)
    }

    // 提示用户选择网卡
    fmt.Print("Enter the number of the interface to listen on: ")
    reader := bufio.NewReader(os.Stdin)
    input, _ := reader.ReadString('\n')
    input = strings.TrimSpace(input)

    // 解析用户输入的序号
    index, err := strconv.Atoi(input)
    if err != nil || index < 1 || index > len(devices) {
        logger.Fatal("Invalid interface number")
    }

    // 选择网卡
    device := devices[index-1]
    logger.Print("开始抓包：\r\n")
    // 打开网络接口
    handle, err = pcap.OpenLive(device.Name, snapshotLen, promiscuous, timeout)
    if err != nil {
        logger.Fatal(err)
    }
    defer handle.Close()

    // 设置过滤器，只捕获ARP数据包
    filter := "arp"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }

    // 处理数据包
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        printPacketInfo(packet)
    }
}

func printPacketInfo(packet gopacket.Packet) {
    arpLayer := packet.Layer(layers.LayerTypeARP)
    if arpLayer != nil {
        arp := arpLayer.(*layers.ARP)
        srcIP := net.IP(arp.SourceProtAddress).String()
        srcMAC := net.HardwareAddr(arp.SourceHwAddress).String()
        // 增加判断，对于自己发出来判断IP地址是否有人使用的这种包，不做处理，直接返回。
        if srcIP == "0.0.0.0" {
            return
        }
        // 打印IP地址和MAC地址
        fmt.Printf("IP: %s, MAC: %s\n", srcIP, srcMAC)

        // 检查IP地址冲突
        if mac, ok := ipMap[srcIP]; ok && mac != srcMAC {
            printConflictInfo("IP", srcIP, mac, srcMAC)
        } else {
            ipMap[srcIP] = srcMAC
        }

        // 检查MAC地址冲突
        if ip, ok := macMap[srcMAC]; ok && ip != srcIP {
            printConflictInfo("MAC", srcMAC, ip, srcIP)
        } else {
            macMap[srcMAC] = srcIP
        }
    }
}

func printConflictInfo(conflictType, key, oldValue, newValue string) {
    errorMsg := fmt.Sprintf("\033[31m%s冲突: %s 之前为 %s, 现在为 %s\033[0m\r\n", conflictType, key, oldValue, newValue)
    errorMsg2 := fmt.Sprintf("%s冲突: %s 之前为 %s, 现在为 %s\r\n", conflictType, key, oldValue, newValue)
    fmt.Print(errorMsg)

    if logEnabled {
        logger.Print(errorMsg2)
    }
}
