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

func JDWPScan(info *structs.HostInfo) (err error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	client, err := common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(6)*time.Second)
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	if err != nil {
		return err
	}

	err = client.SetDeadline(time.Now().Add(time.Duration(6) * time.Second))
	if err != nil {
		return err
	}
	_, err = client.Write([]byte("JDWP-Handshake"))
	gologger.AuditTimeLogger("[Go] [JDWP] [1/3] Dumped TCP request for %s\n\n%s\n", realhost, hex.Dump([]byte("JDWP-Handshake")))
	if err != nil {
		return err
	}

	rev := make([]byte, 1024)
	n, errRead := client.Read(rev)
	if errRead != nil {
		return errRead
	}
	gologger.AuditTimeLogger("[Go] [JDWP] [1/3] Dumped TCP response for %s\n\n%s\n", realhost, hex.Dump(rev[:n]))
	if !strings.Contains(string(rev[:n]), "JDWP-Handshake") {
		// 不是JDWP
		return err
	}

	_, err = client.Write([]byte("\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x01\x07"))
	gologger.AuditTimeLogger("[Go] [JDWP] [2/3] Dumped TCP request for %s\n\n%s\n", realhost, hex.Dump([]byte("\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x01\x07")))
	if err != nil {
		return err
	}

	rev = make([]byte, 1024)
	n, errRead = client.Read(rev)
	if errRead != nil {
		return errRead
	}
	if n == 0 {
		return err
	}
	gologger.AuditTimeLogger("[Go] [JDWP] [2/3] Dumped TCP response for %s\n\n%s\n", realhost, hex.Dump(rev[:n]))
	_, err = client.Write([]byte("\x00\x00\x00\x0b\x00\x00\x00\x03\x00\x01\x01"))
	gologger.AuditTimeLogger("[Go] [JDWP] [3/3] Dumped TCP request for %s\n\n%s\n", realhost, hex.Dump([]byte("\x00\x00\x00\x0b\x00\x00\x00\x03\x00\x01\x01")))
	if err != nil {
		return err
	}

	rev = make([]byte, 1024)
	n, errRead = client.Read(rev)
	if errRead != nil {
		return errRead
	}
	gologger.AuditTimeLogger("[Go] [JDWP] [3/3] Dumped TCP response for %s\n\n%s\n", realhost, hex.Dump(rev[:n]))
	data := string(rev[:n])
	if !strings.Contains(data, "Java Debug Wire Protocol") {
		return err
	}

	javaInfo := data[15:]
	result := fmt.Sprintf("JDWP://%s Unauthorized", realhost)
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
		GoPoc: ddout.GoPocsResultType{PocName: "JDWP-Unauthorized",
			Security:    "CRITICAL",
			Target:      realhost,
			InfoLeft:    javaInfo,
			Description: "JDWP未授权访问,可尝试RCE",
			ShowMsg:     result},
		AdditionalMsg: "",
	})

	GoPocWriteResult(structs.GoPocsResultType{
		PocName:     "JDWP-Unauthorized",
		Security:    "CRITICAL",
		Target:      realhost,
		InfoLeft:    javaInfo,
		Description: "JDWP未授权访问,可尝试RCE",
	})

	return err
}
