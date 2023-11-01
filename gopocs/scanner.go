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

func AddScan(scantype string, info structs.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
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
	f := reflect.ValueOf(PluginList[*name])
	in := []reflect.Value{reflect.ValueOf(info)}
	f.Call(in)
}

func GoPocsDispatcher(nucleiResults []output.ResultEvent) {
	if len(structs.GlobalIPPortMap) == 0 && len(nucleiResults) == 0 {
		return
	}

	initDic()

	var ch = make(chan struct{}, structs.GlobalConfig.GoPocThreads)
	var wg = sync.WaitGroup{}
	gologger.Info().Msg("Golang Poc引擎启动")

	// 各类协议

	for hostPort, protocol := range structs.GlobalIPPortMap {
		t := strings.Split(hostPort, ":")
		host := t[0]
		port := t[1]

		if protocol == "ssh" {
			AddScan("SSH-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		} else if protocol == "ftp" {
			AddScan("FTP-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		} else if protocol == "mysql" {
			AddScan("Mysql-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		} else if protocol == "mssql" {
			AddScan("Mssql-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		} else if protocol == "oracle" {
			AddScan("Oracle-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		} else if protocol == "mongodb" {
			AddScan("MongoDB-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		} else if protocol == "rdp" {
			AddScan("RDP-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		} else if protocol == "redis" {
			AddScan("Redis-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		} else if protocol == "smb" || port == "445" {
			AddScan("SMB-MS17-010",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
			AddScan("SMB-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		} else if protocol == "postgresql" {
			AddScan("PostgreSQL-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		} else if protocol == "telnet" {
			AddScan("Telnet-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		} else if protocol == "memcached" {
			AddScan("Memcache-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		} else if protocol == "netbios" || port == "445" {
			AddScan("NetBios-GetHostInfo",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		} else if protocol == "rpc" {
			AddScan("RPC-GetHostInfo",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		} else if protocol == "jdwp" {
			AddScan("JDWP-Scan",
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
