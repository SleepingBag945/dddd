package gonmap

import (
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

var nmap *Nmap

var ProbesCount = 0     //探针数
var MatchCount = 0      //指纹数
var UsedProbesCount = 0 //已使用探针数
var UsedMatchCount = 0  //已使用指纹数

var logger = Logger(log.New(os.Stderr, "[gonmap] ", log.Ldate|log.Ltime|log.Lshortfile))

type Logger interface {
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}

// r["PROBE"] 总探针数、r["MATCH"] 总指纹数 、r["USED_PROBE"] 已使用探针数、r["USED_MATCH"] 已使用指纹数
func init() {
	initWithFilter(9)
}

func initWithFilter(filter int) {
	//初始化NMAP探针库
	repairNMAPString()
	nmap = &Nmap{
		exclude:      emptyPortList,
		probeNameMap: make(map[string]*probe),
		probeSort:    []string{},
		portProbeMap: make(map[int]ProbeList),

		filter:  filter,
		timeout: time.Second,

		probeUsed:          emptyProbeList,
		bypassAllProbePort: []int{161, 137, 139, 135, 389, 443, 548, 1433, 6379, 1883, 5432, 1521, 3389, 3388, 3389, 33890, 33900},
		sslSecondProbeMap:  []string{"TCP_TerminalServerCookie", "TCP_TerminalServer"},
		allProbeMap:        []string{"TCP_GetRequest", "TCP_NULL", "TCP_JDWP", "TCP_redis-server", "TCP_ms-sql-s", "TCP_adbConnect"},
		sslProbeMap:        []string{"TCP_TLSSessionReq", "TCP_SSLSessionReq", "TCP_SSLv23SessionReq"},
	}
	for i := 0; i <= 65535; i++ {
		nmap.portProbeMap[i] = []string{}
	}
	nmap.loads(nmapServiceProbes + nmapCustomizeProbes)
	//修复fallback
	nmap.fixFallback()
	//新增自定义指纹信息
	customNMAPMatch()
	//优化检测逻辑，及端口对应的默认探针
	optimizeNMAPProbes()
	//排序
	nmap.sslSecondProbeMap = nmap.sortOfRarity(nmap.sslSecondProbeMap)
	nmap.allProbeMap = nmap.sortOfRarity(nmap.allProbeMap)
	nmap.sslProbeMap = nmap.sortOfRarity(nmap.sslProbeMap)
	for index, value := range nmap.portProbeMap {
		nmap.portProbeMap[index] = nmap.sortOfRarity(value)
	}
	//输出统计数据状态
	statistical()
}

func statistical() {
	ProbesCount = len(nmap.probeSort)
	for _, p := range nmap.probeNameMap {
		MatchCount += len(p.matchGroup)
	}
	UsedProbesCount = len(nmap.portProbeMap[0])
	for _, p := range nmap.portProbeMap[0] {
		UsedMatchCount += len(nmap.probeNameMap[p].matchGroup)
	}
}

func repairNMAPString() {
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, "${backquote}", "`")
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `q|GET / HTTP/1.0\r\n\r\n|`,
		`q|GET / HTTP/1.0\r\nHost: {Host}\r\nUser-Agent: Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)\r\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\nAccept: */*\r\n\r\n|`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `\1`, `$1`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?=\\)`, `(?:\\)`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?=[\w._-]{5,15}\r?\n$)`, `(?:[\w._-]{5,15}\r?\n$)`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?:[^\r\n]*r\n(?!\r\n))*?`, `(?:[^\r\n]+\r\n)*?`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?:[^\r\n]*\r\n(?!\r\n))*?`, `(?:[^\r\n]+\r\n)*?`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?:[^\r\n]+\r\n(?!\r\n))*?`, `(?:[^\r\n]+\r\n)*?`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!2526)`, ``)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!400)`, ``)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!\0\0)`, ``)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!/head>)`, ``)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!HTTP|RTSP|SIP)`, ``)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!.*[sS][sS][hH]).*`, `.*`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!\xff)`, `.`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!x)`, `[^x]`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?<=.)`, `(?:.)`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?<=\?)`, `(?:\?)`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `\x20\x02\x00.`, `\x20\x02..`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `match rtmp`, `# match rtmp`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `nmap`, `pamn`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `Nmap`, `pamn`)
}

func customNMAPMatch() {
	//新增自定义指纹信息
	nmap.AddMatch("TCP_GetRequest", `echo m|^GET / HTTP/1.0\r\n\r\n$|s`)
	nmap.AddMatch("TCP_GetRequest", `mongodb m|.*It looks like you are trying to access MongoDB.*|s p/MongoDB/`)
	nmap.AddMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]+\r\n)*?Server: ([^\r\n]+)| p/$1/`)
	nmap.AddMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d|`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MariaDB server| p/MariaDB/`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MySQL server| p/MySQL/`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a(\d+\.\d+\.\d+)\x00.*caching_sha2_password\x00| p/MariaDB/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a(\d+\.\d+\.\d+)\x00.*caching_sha2_password\x00| p/MariaDB/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a([\d.-]+)-MariaDB\x00.*mysql_native_password\x00| p/MariaDB/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `redis m|-DENIED Redis is running in.*| p/Redis/ i/Protected mode/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Welcome to visit (.*) series router!.*|s p/$1 Router/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^Username: ??|`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Telnet service is disabled or Your telnet session has expired due to inactivity.*|s i/Disabled/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Telnet connection from (.*) refused.*|s i/Refused/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Command line is locked now, please retry later.*\x0d\x0a\x0d\x0a|s i/Locked/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet.*|s`)
	nmap.AddMatch("TCP_NULL", `telnet m|^telnetd:|s`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Quopin CLI for (.*)\x0d\x0a\x0d\x0a|s p/$1/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^\x0d\x0aHello, this is FRRouting \(version ([\d.]+)\).*|s p/FRRouting/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*User Access Verification.*Username:|s`)
	nmap.AddMatch("TCP_NULL", `telnet m|^Connection failed.  Windows CE Telnet Service cannot accept anymore concurrent users.|s o/Windows/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^\x0d\x0a\x0d\x0aWelcome to the host.\x0d\x0a.*|s o/Windows/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Welcome Visiting Huawei Home Gateway\x0d\x0aCopyright by Huawei Technologies Co., Ltd.*Login:|s p/Huawei/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^..\x01..\x03..\x18..\x1f|s p/Huawei/`)
	nmap.AddMatch("TCP_NULL", `smtp m|^220 ([a-z0-1.-]+).*| h/$1/`)
	nmap.AddMatch("TCP_NULL", `ftp m|^220 H3C Small-FTP Server Version ([\d.]+).* | p/H3C Small-FTP/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `ftp m|^421[- ]Service not available..*|`)
	nmap.AddMatch("TCP_NULL", `ftp m|^220[- ].*filezilla.*|i p/FileZilla/`)
	nmap.AddMatch("TCP_TerminalServerCookie", `ms-wbt-server m|^\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02.*\0\x02\0\0\0| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a`)
	nmap.AddMatch("TCP_redis-server", `redis m|^.*redis_version:([.\d]+)\n|s p/Redis key-value store/ v/$1/ cpe:/a:redislabs:redis:$1/`)
	nmap.AddMatch("TCP_redis-server", `redis m|^-NOAUTH Authentication required.|s p/Redis key-value store/`)
}

func optimizeNMAPProbes() {
	nmap.probeNameMap["TCP_GenericLines"].sslports = nmap.probeNameMap["TCP_GenericLines"].sslports.append(993, 994, 456, 995)
	//优化检测逻辑，及端口对应的默认探针
	nmap.portProbeMap[993] = append([]string{"TCP_GenericLines"}, nmap.portProbeMap[993]...)
	nmap.portProbeMap[994] = append([]string{"TCP_GenericLines"}, nmap.portProbeMap[994]...)
	nmap.portProbeMap[995] = append([]string{"TCP_GenericLines"}, nmap.portProbeMap[995]...)
	nmap.portProbeMap[465] = append([]string{"TCP_GenericLines"}, nmap.portProbeMap[465]...)
	nmap.portProbeMap[3390] = append(nmap.portProbeMap[3390], "TCP_TerminalServer")
	nmap.portProbeMap[3390] = append(nmap.portProbeMap[3390], "TCP_TerminalServerCookie")
	nmap.portProbeMap[33890] = append(nmap.portProbeMap[33890], "TCP_TerminalServer")
	nmap.portProbeMap[33890] = append(nmap.portProbeMap[33890], "TCP_TerminalServerCookie")
	nmap.portProbeMap[33900] = append(nmap.portProbeMap[33900], "TCP_TerminalServer")
	nmap.portProbeMap[33900] = append(nmap.portProbeMap[33900], "TCP_TerminalServerCookie")
	nmap.portProbeMap[7890] = append(nmap.portProbeMap[7890], "TCP_Socks5")
	nmap.portProbeMap[7891] = append(nmap.portProbeMap[7891], "TCP_Socks5")
	nmap.portProbeMap[4000] = append(nmap.portProbeMap[4000], "TCP_Socks5")
	nmap.portProbeMap[2022] = append(nmap.portProbeMap[2022], "TCP_Socks5")
	nmap.portProbeMap[6000] = append(nmap.portProbeMap[6000], "TCP_Socks5")
	nmap.portProbeMap[7000] = append(nmap.portProbeMap[7000], "TCP_Socks5")

	//将TCP_GetRequest的fallback参数设置为NULL探针，避免漏资产
	nmap.probeNameMap["TCP_GenericLines"].fallback = "TCP_NULL"
	nmap.probeNameMap["TCP_GetRequest"].fallback = "TCP_NULL"
	nmap.probeNameMap["TCP_TerminalServerCookie"].fallback = "TCP_GetRequest"
	nmap.probeNameMap["TCP_TerminalServer"].fallback = "TCP_GetRequest"
}

// 配置类
func SetFilter(filter int) {
	initWithFilter(filter)
}

func SetLogger(v Logger) {
	logger = v
}

// 功能类
func New() *Nmap {
	n := *nmap
	return &n
}

func GuessProtocol(port int) string {
	protocol := nmapServices[port]
	if protocol == "unknown" {
		protocol = "http"
	}
	return protocol
}

var regexpFirstNum = regexp.MustCompile(`^\d`)

func FixProtocol(oldProtocol string) string {
	//进行最后输出修饰
	if oldProtocol == "ssl/http" {
		return "https"
	}
	if oldProtocol == "http-proxy" {
		return "http"
	}
	if oldProtocol == "ms-wbt-server" {
		return "rdp"
	}
	if oldProtocol == "microsoft-ds" {
		return "smb"
	}
	if oldProtocol == "netbios-ssn" {
		return "netbios"
	}
	if oldProtocol == "oracle-tns" {
		return "oracle"
	}
	if oldProtocol == "msrpc" {
		return "rpc"
	}
	if oldProtocol == "ms-sql-s" {
		return "mssql"
	}
	if oldProtocol == "domain" {
		return "dns"
	}
	if oldProtocol == "svnserve" {
		return "svn"
	}
	if oldProtocol == "ibm-db2" {
		return "db2"
	}
	if oldProtocol == "socks-proxy" {
		return "socks5"
	}
	if len(oldProtocol) > 4 {
		if oldProtocol[:4] == "ssl/" {
			return oldProtocol[4:] + "-ssl"
		}
	}
	if regexpFirstNum.MatchString(oldProtocol) {
		oldProtocol = "S" + oldProtocol
	}
	oldProtocol = strings.ReplaceAll(oldProtocol, "_", "-")
	return oldProtocol
}
