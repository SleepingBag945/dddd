package gopocs

import (
	"dddd/structs"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"reflect"
	"strings"
	"sync"
)

var Mutex = &sync.Mutex{}

// 单线程的
var currentCount = 0

func AddScan(scantype string, info structs.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	currentCount += 1
	if currentCount%100 == 0 {
		gologger.Info().Msgf("[GoPoc] 当前进度: %v %v [%v/%v]", scantype, info.Host+":"+info.Ports, currentCount, allCount)
	}

	*ch <- struct{}{}
	wg.Add(1)
	go func() {
		Mutex.Lock()
		structs.AddScanNum += 1
		Mutex.Unlock()
		ScanFunc(&scantype, &info)
		Mutex.Lock()
		structs.AddScanEnd += 1
		Mutex.Unlock()
		wg.Done()
		<-*ch
	}()
}

func ScanFunc(name *string, info *structs.HostInfo) {
	defer func() {
		if err := recover(); err != nil {
			gologger.Error().Msgf("[-] %v:%v %v error: %v\n", info.Host, info.Ports, name, err)
		}
	}()
	f := reflect.ValueOf(PluginList[*name])
	in := []reflect.Value{reflect.ValueOf(info)}
	f.Call(in)
}

var allCount = 0

func GoPocsDispatcher(nucleiResults []output.ResultEvent) {
	if len(structs.GlobalIPPortMap) == 0 && len(nucleiResults) == 0 {
		return
	}

	initDic()

	allCount = len(structs.GlobalIPPortMap) + len(nucleiResults)

	var ch = make(chan struct{}, structs.GlobalConfig.GoPocThreads)
	var wg = sync.WaitGroup{}
	gologger.Info().Msg("Golang Poc引擎启动")

	// 各类协议

	for hostPort, protocol := range structs.GlobalIPPortMap {
		t := strings.Split(hostPort, ":")
		host := t[0]
		port := t[1]

		if protocol == "ssh" || port == "22" {
			AddScan("SSH-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "ftp" || port == "21" {
			AddScan("FTP-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "mysql" || port == "3306" {
			AddScan("Mysql-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "mssql" || port == "1433" {
			AddScan("Mssql-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "oracle" || port == "1521" {
			AddScan("Oracle-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "mongodb" || port == "27017" {
			AddScan("MongoDB-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "rdp" || port == "3389" {
			if structs.GlobalConfig.NoServiceBruteForce {
				continue
			}
			AddScan("RDP-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "redis" || port == "6379" {
			// 有未授权检测
			AddScan("Redis-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "smb" || port == "445" {
			AddScan("SMB-MS17-010",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
			AddScan("SMB-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "postgresql" || port == "5432" {
			AddScan("PostgreSQL-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "telnet" || port == "23" {
			AddScan("Telnet-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "memcached" || port == "11211" {
			AddScan("Memcache-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "netbios" || port == "445" {
			AddScan("NetBios-GetHostInfo",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "rpc" {
			AddScan("RPC-GetHostInfo",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "jdwp" {
			AddScan("JDWP-Scan",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "adb" || port == "5555" {
			AddScan("ADB-Scan",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}

	}

	// 各类指纹
	//for host, fingers := range structs.GlobalResultMap {
	//
	//}

	for _, result := range nucleiResults {
		if result.TemplateID == "shiro-detect" {
			AddScan("Shiro-Key-Crack",
				structs.HostInfo{Url: result.Matched},
				&ch, &wg)
		}
	}

	wg.Wait()
}
