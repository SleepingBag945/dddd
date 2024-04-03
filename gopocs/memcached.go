package gopocs

import (
	"dddd/common"
	"dddd/ddout"
	"dddd/structs"
	"encoding/hex"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"strings"
	"time"
)

func MemcachedScan(info *structs.HostInfo) (err error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	client, err := common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(6)*time.Second)
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	if err == nil {
		err = client.SetDeadline(time.Now().Add(time.Duration(6) * time.Second))
		if err == nil {
			_, err = client.Write([]byte("stats\n")) //Set the key randomly to prevent the key on the server from being overwritten
			gologger.AuditTimeLogger("[Go] [Memcached] Dumped TCP request for %s\n\n%s\n", realhost, hex.Dump([]byte("stats\n")))
			if err == nil {
				rev := make([]byte, 1024)
				n, errRead := client.Read(rev)
				if errRead == nil {
					gologger.AuditTimeLogger("[Go] [Memcached] Dumped TCP response for %s\n\n%s\n", realhost, hex.Dump(rev[:n]))
					if strings.Contains(string(rev[:n]), "STAT") {
						result := fmt.Sprintf("Memcached://%s Unauthorized", realhost)
						// gologger.Silent().Msg(result)

						ddout.FormatOutput(ddout.OutputMessage{
							Type:     "GoPoc",
							IP:       "",
							IPs:      nil,
							Port:     "",
							Protocol: "",
							Web:      ddout.WebInfo{},
							Finger:   nil,
							Domain:   "",
							GoPoc: ddout.GoPocsResultType{PocName: "Memcached-Unauthorized",
								Security:    "HIGH",
								Target:      realhost,
								InfoLeft:    string(rev[:n]),
								Description: "Memcached未授权访问",
								ShowMsg:     result},
							AdditionalMsg: "",
						})

						GoPocWriteResult(structs.GoPocsResultType{
							PocName:     "Memcached-Unauthorized",
							Security:    "HIGH",
							Target:      realhost,
							InfoLeft:    string(rev[:n]),
							Description: "Memcached未授权访问",
						})

					}
				}
			}
		}
	}
	return err
}
