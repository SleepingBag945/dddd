package gonmap

import (
	"errors"
	"fmt"
	"github.com/lcvvvv/gonmap/simplenet"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type probe struct {
	//探针级别
	rarity int
	//探针名称
	name string
	//探针适用默认端口号
	ports PortList
	//探针适用SSL端口号
	sslports PortList

	//totalwaitms  time.Duration
	//tcpwrappedms time.Duration

	//探针对应指纹库
	matchGroup []*match
	//探针指纹库若匹配失败，则会尝试使用fallback指定探针的指纹库
	fallback string

	//探针发送协议类型
	protocol string
	//探针发送数据
	sendRaw string
}

func (p *probe) scan(host string, port int, tls bool, timeout time.Duration, size int) (string, bool, error) {
	uri := fmt.Sprintf("%s:%d", host, port)

	sendRaw := strings.Replace(p.sendRaw, "{Host}", fmt.Sprintf("%s:%d", host, port), -1)

	text, err := simplenet.Send(p.protocol, tls, uri, sendRaw, timeout, size)
	if err == nil {
		return text, tls, nil
	}
	if strings.Contains(err.Error(), "STEP1") && tls == true {
		text, err := simplenet.Send(p.protocol, false, uri, p.sendRaw, timeout, size)
		return text, false, err
	}
	return text, tls, err
}

func (p *probe) match(s string) *FingerPrint {
	var f = &FingerPrint{}
	var softFilter string

	for _, m := range p.matchGroup {
		//实现软筛选
		if softFilter != "" {
			if m.service != softFilter {
				continue
			}
		}
		//logger.Println("开始匹配正则：", m.service, m.patternRegexp.String())
		if m.patternRegexp.MatchString(s) {
			//标记当前正则
			f.MatchRegexString = m.patternRegexp.String()
			if m.soft {
				//如果为软捕获，这设置筛选器
				f.Service = m.service
				softFilter = m.service
				continue
			} else {
				//如果为硬捕获则直接获取指纹信息
				m.makeVersionInfo(s, f)
				f.Service = m.service
				return f
			}
		}
	}
	return f
}

var probeExprRegx = regexp.MustCompile("^(UDP|TCP) ([a-zA-Z0-9-_./]+) (?:q\\|([^|]*)\\|)$")
var probeIntRegx = regexp.MustCompile(`^(\d+)$`)
var probeStrRegx = regexp.MustCompile(`^([a-zA-Z0-9-_./]+)$`)

func parseProbe(lines []string) *probe {
	var p = &probe{}
	p.ports = emptyPortList
	p.sslports = emptyPortList
	for _, line := range lines {
		p.loadLine(line)
	}
	return p
}

func (p *probe) loadLine(s string) {
	//分解命令
	i := strings.Index(s, " ")
	commandName := s[:i]
	commandArgs := s[i+1:]
	//逐行处理
	switch commandName {
	case "Probe":
		p.loadProbe(commandArgs)
	case "match":
		p.loadMatch(commandArgs, false)
	case "softmatch":
		p.loadMatch(commandArgs, true)
	case "ports":
		p.loadPorts(commandArgs, false)
	case "sslports":
		p.loadPorts(commandArgs, true)
	case "totalwaitms":
		//p.totalwaitms = time.Duration(p.getInt(commandArgs)) * time.Millisecond
	case "tcpwrappedms":
		//p.tcpwrappedms = time.Duration(p.getInt(commandArgs)) * time.Millisecond
	case "rarity":
		p.rarity = p.getInt(commandArgs)
	case "fallback":
		p.fallback = p.getString(commandArgs)
	}
}

func (p *probe) loadProbe(s string) {
	//Probe <protocol> <probename> <probestring>
	if !probeExprRegx.MatchString(s) {
		panic(errors.New("probe 语句格式不正确"))
	}
	args := probeExprRegx.FindStringSubmatch(s)
	if args[1] == "" || args[2] == "" {
		panic(errors.New("probe 参数格式不正确"))
	}
	p.protocol = args[1]
	p.name = args[1] + "_" + args[2]
	str := args[3]
	str = strings.ReplaceAll(str, `\0`, `\x00`)
	str = strings.ReplaceAll(str, `"`, `${double-quoted}`)
	str = `"` + str + `"`
	str, _ = strconv.Unquote(str)
	str = strings.ReplaceAll(str, `${double-quoted}`, `"`)
	p.sendRaw = str
}

func (p *probe) loadMatch(s string, soft bool) {
	//"match": misc.MakeRegexpCompile("^([a-zA-Z0-9-_./]+) m\\|([^|]+)\\|([is]{0,2}) (.*)$"),
	//match <Service> <pattern>|<patternopt> [<versioninfo>]
	//	"matchVersioninfoProductname": misc.MakeRegexpCompile("p/([^/]+)/"),
	//	"matchVersioninfoVersion":     misc.MakeRegexpCompile("v/([^/]+)/"),
	//	"matchVersioninfoInfo":        misc.MakeRegexpCompile("i/([^/]+)/"),
	//	"matchVersioninfoHostname":    misc.MakeRegexpCompile("h/([^/]+)/"),
	//	"matchVersioninfoOS":          misc.MakeRegexpCompile("o/([^/]+)/"),
	//	"matchVersioninfoDevice":      misc.MakeRegexpCompile("d/([^/]+)/"),

	p.matchGroup = append(p.matchGroup, parseMatch(s, soft))
}

func (p *probe) loadPorts(expr string, ssl bool) {
	if ssl {
		p.sslports = parsePortList(expr)
	} else {
		p.ports = parsePortList(expr)
	}
}

func (p *probe) getInt(expr string) int {
	if !probeIntRegx.MatchString(expr) {
		panic(errors.New("totalwaitms or tcpwrappedms 语句参数不正确"))
	}
	i, _ := strconv.Atoi(probeIntRegx.FindStringSubmatch(expr)[1])
	return i
}

func (p *probe) getString(expr string) string {
	if !probeStrRegx.MatchString(expr) {
		panic(errors.New("fallback 语句参数不正确"))
	}
	return probeStrRegx.FindStringSubmatch(expr)[1]
}
