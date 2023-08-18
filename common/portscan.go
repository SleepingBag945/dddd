package common

import (
	"bytes"
	"dddd/lib/masscan"
	"dddd/structs"
	"dddd/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

func ParsePort(ports string) (scanPorts []int) {
	if ports == "" {
		return
	}
	slices := strings.Split(ports, ",")
	for _, port := range slices {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				continue
			}

			startPort, _ := strconv.Atoi(ranges[0])
			endPort, _ := strconv.Atoi(ranges[1])
			if startPort < endPort {
				port = ranges[0]
				upper = ranges[1]
			} else {
				port = ranges[1]
				upper = ranges[0]
			}
		}
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := start; i <= end; i++ {
			scanPorts = append(scanPorts, i)
		}
	}
	scanPorts = utils.RemoveDuplicateElementInt(scanPorts)
	return scanPorts
}

func PortScanTCP(IPs []string, Ports string, timeout int) []string {
	var AliveAddress []string
	probePorts := ParsePort(Ports)

	workers := structs.GlobalConfig.TCPPortScanThreads
	Addrs := make(chan Addr, len(IPs)*len(probePorts))
	results := make(chan string, len(IPs)*len(probePorts))
	var wg sync.WaitGroup

	//接收结果
	go func() {
		for found := range results {
			AliveAddress = append(AliveAddress, found)
			wg.Done()
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range Addrs {
				PortConnect(addr, results, timeout, &wg)
				wg.Done()
			}
		}()
	}

	//添加扫描目标
	for _, port := range probePorts {
		for _, host := range IPs {
			wg.Add(1)
			Addrs <- Addr{host, port}
		}
	}
	wg.Wait()
	close(Addrs)
	close(results)

	return AliveAddress
}

type Addr struct {
	ip   string
	port int
}

func PortConnect(addr Addr, respondingHosts chan<- string, adjustedTimeout int, wg *sync.WaitGroup) {
	host, port := addr.ip, addr.port
	conn, err := WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err == nil {
		address := host + ":" + strconv.Itoa(port)
		gologger.Silent().Msgf("[PortScan] %v", address)
		wg.Add(1)
		respondingHosts <- address
	}
}

func PortScanSYN(IPs []string) []string {
	ips := strings.Join(utils.RemoveDuplicateElement(IPs), "\n")
	err := os.WriteFile("masscan_tmp.txt", []byte(ips), 0666)
	if err != nil {
		return []string{}
	}
	defer os.Remove("masscan_tmp.txt")

	ms := masscan.New(structs.GlobalConfig.MasscanPath)
	ms.SetFileName("masscan_tmp.txt")
	ms.SetPorts("1-65535")
	ms.SetRate(strconv.Itoa(structs.GlobalConfig.SYNPortScanThreads))
	gologger.Info().Msgf("开始SYN端口扫描")
	err = ms.Run()
	if err != nil {
		return []string{}
	}
	hosts, errParse := ms.Parse()
	if errParse != nil {
		gologger.Error().Msgf("masscan结果解析失败")
		return []string{}
	}

	var results []string
	for _, each := range hosts {
		for _, port := range each.Ports {
			results = append(results, each.Address.Addr+":"+port.Portid)
		}
	}
	results = utils.RemoveDuplicateElement(results)
	for _, each := range results {
		gologger.Silent().Msg("[PortScan] " + each)
	}
	return results
}

// CheckMasScan 校验MasScan是否正确安装
func CheckMasScan() bool {
	var bsenv = ""
	if OS != "windows" {
		bsenv = "/bin/bash"
	}

	var command *exec.Cmd
	if OS == "windows" {
		command = exec.Command("cmd", "/c", structs.GlobalConfig.MasscanPath)
	} else if OS == "linux" {
		command = exec.Command(bsenv, "-c", structs.GlobalConfig.MasscanPath)
	} else if OS == "darwin" {
		command = exec.Command(bsenv, "-c", structs.GlobalConfig.MasscanPath)
	}
	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	err := command.Start()
	if err != nil {
		gologger.Error().Msgf("未检测到路径 %v 存在masscan", structs.GlobalConfig.MasscanPath)
		return false
	}
	_ = command.Wait()

	// 未检测到masscan的默认banner
	if !strings.Contains(outinfo.String(), "masscan -p80,8000-8100 10.0.0.0/8 --rate=10000") {
		gologger.Error().Msgf("未检测到路径 %v 存在masscan", structs.GlobalConfig.MasscanPath)
		return false
	}

	return true
}

func RemoveFirewall(ipPorts []string) []string {
	var results []string

	m := make(map[string][]string)
	for _, ipPort := range ipPorts {
		t := strings.Split(ipPort, ":")
		ip := t[0]
		port := t[1]

		_, ok := m[ip]
		if !ok {
			m[ip] = []string{port}
		} else {
			m[ip] = append(m[ip], port)
		}
	}

	for ip, ports := range m {
		ps := utils.RemoveDuplicateElement(ports)
		if len(ps) >= structs.GlobalConfig.PortsThreshold {
			gologger.Error().Msgf("%s 端口数量超出阈值,已丢弃", ip)
			continue
		}
		for _, p := range ports {
			results = append(results, ip+":"+p)
		}
	}
	return utils.RemoveDuplicateElement(results)
}
