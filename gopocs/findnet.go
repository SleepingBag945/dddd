package gopocs

import (
	"bytes"
	"dddd/common"
	"dddd/ddout"
	"dddd/structs"
	"encoding/hex"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	bufferV1, _ = hex.DecodeString("05000b03100000004800000001000000b810b810000000000100000000000100c4fefc9960521b10bbcb00aa0021347a00000000045d888aeb1cc9119fe808002b10486002000000")
	bufferV2, _ = hex.DecodeString("050000031000000018000000010000000000000000000500")
	bufferV3, _ = hex.DecodeString("0900ffff0000")
)

func Findnet(info *structs.HostInfo) error {
	err := FindnetScan(info)
	return err
}

func FindnetScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(6)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return err
	}
	err = conn.SetDeadline(time.Now().Add(time.Duration(6) * time.Second))
	if err != nil {
		return err
	}
	_, err = conn.Write(bufferV1)
	gologger.AuditTimeLogger("[Go] [WMI-Leak] [1/2] Dumped TCP request for %s\n\n%s\n", realhost, hex.Dump(bufferV1))
	if err != nil {
		return err
	}

	reply := make([]byte, 4096)
	_, err = conn.Read(reply)
	if err != nil {
		return err
	}
	gologger.AuditTimeLogger("[Go] [WMI-Leak] [1/2] Dumped TCP response for %s\n\n%s\n", realhost, hex.Dump(reply))
	_, err = conn.Write(bufferV2)
	gologger.AuditTimeLogger("[Go] [WMI-Leak] [2/2] Dumped TCP request for %s\n\n%s\n", realhost, hex.Dump(bufferV2))
	if err != nil {
		return err
	}
	if n, err := conn.Read(reply); err != nil || n < 42 {
		return err
	}
	gologger.AuditTimeLogger("[Go] [WMI-Leak] [2/2] Dumped TCP response for %s\n\n%s\n", realhost, hex.Dump(reply))
	text := reply[42:]
	flag := true
	for i := 0; i < len(text)-5; i++ {
		if bytes.Equal(text[i:i+6], bufferV3) {
			text = text[:i-4]
			flag = false
			break
		}
	}
	if flag {
		return err
	}
	err = read(text, info.Host)
	return err
}

func HexUnicodeStringToString(src string) string {
	sText := ""
	if len(src)%4 != 0 {
		src += src[:len(src)-len(src)%4]
	}
	for i := 0; i < len(src); i = i + 4 {
		sText += "\\u" + src[i+2:i+4] + src[i:i+2]
	}

	textUnquoted := sText
	sUnicodev := strings.Split(textUnquoted, "\\u")
	var context string
	for _, v := range sUnicodev {
		if len(v) < 1 {
			continue
		}
		temp, err := strconv.ParseInt(v, 16, 32)
		if err != nil {
			return ""
		}
		context += fmt.Sprintf("%c", temp)
	}
	return context
}

func read(text []byte, host string) error {
	encodedStr := hex.EncodeToString(text)

	hn := ""
	for i := 0; i < len(encodedStr)-4; i = i + 4 {
		if encodedStr[i:i+4] == "0000" {
			break
		}
		hn += encodedStr[i : i+4]
	}

	var name string
	name = HexUnicodeStringToString(hn)

	if name == "" {
		name = "GetNameError"
	}

	hostnames := strings.Replace(encodedStr, "0700", "", -1)
	hostname := strings.Split(hostnames, "000000")

	var ipInfo []string

	for i := 0; i < len(hostname); i++ {
		hostname[i] = strings.Replace(hostname[i], "00", "", -1)
		hostStr, err := hex.DecodeString(hostname[i])
		if err != nil {
			return err
		}

		if net.ParseIP(string(hostStr)) != nil { // 是IP
			ipInfo = append(ipInfo, string(hostStr))
		}
	}
	result := host + " " + name
	for _, v := range ipInfo {
		result += " => " + v
	}
	// gologger.Silent().Msg("[GoPoc] RPC:" + result)
	ddout.FormatOutput(ddout.OutputMessage{
		Type:     "GoPoc",
		IP:       "",
		IPs:      nil,
		Port:     "",
		Protocol: "",
		Web:      ddout.WebInfo{},
		Finger:   nil,
		Domain:   "",
		GoPoc: ddout.GoPocsResultType{PocName: "WMI-Leak",
			Security:    "INFO",
			Target:      host,
			InfoLeft:    strings.ReplaceAll(result, "=>", "\n"),
			Description: "WMI服务泄露了主机名、网卡信息",
			ShowMsg:     result},
		AdditionalMsg: "",
	})

	GoPocWriteResult(structs.GoPocsResultType{
		PocName:     "WMI-Leak",
		Security:    "INFO",
		Target:      host,
		InfoLeft:    strings.ReplaceAll(result, "=>", "\n"),
		Description: "WMI服务泄露了主机名、网卡信息",
	})

	return nil
}
