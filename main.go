package main

import (
	"dddd/common"
	"dddd/common/callnuclei"
	"dddd/common/http"
	"dddd/common/report"
	"dddd/common/uncover"
	"dddd/gopocs"
	"dddd/lib/ddfinger"
	"dddd/structs"
	"dddd/utils"
	"dddd/utils/cdn"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"strings"
)

func main() {
	common.Flag()

	workflow()
}
func workflow() {
	var domains []string
	var urls []string
	var domainPort []string
	var ipPort []string
	var ips []string

	defer gologger.Info().Msg(aurora.BrightGreen("Done!").String())

	searchEngine()

	for _, input := range structs.GlobalConfig.Targets {
		inputType := utils.GetInputType(input)
		if inputType == structs.TypeDomain {
			domains = append(domains, input)
			continue
		} else if inputType == structs.TypeDomainPort {
			domainPort = append(domainPort, input)
			continue
		} else if inputType == structs.TypeCIDR {
			for _, ip := range utils.CIDRToIP(input) {
				ips = append(ips, ip.String())
			}
		} else if inputType == structs.TypeIPRange {
			for _, ip := range utils.RangerToIP(input) {
				ips = append(ips, ip.String())
			}
		} else if inputType == structs.TypeIP {
			ips = append(ips, input)
		} else if inputType == structs.TypeIPPort {
			ipPort = append(ipPort, input)
		} else if inputType == structs.TypeURL {
			urls = append(urls, input)
		}
	}

	if structs.GlobalConfig.Subdomain && len(domains) > 0 {
		subdomains := common.GetSubDomain(domains)
		for _, each := range subdomains {
			domains = append(domains, each)
		}
	}
	domains = utils.RemoveDuplicateElement(domains)

	var cdnDomains []string
	var tIPs []string
	if len(domains) > 0 {
		cdnDomains, _, tIPs = cdn.CheckCDNs(domains, structs.GlobalConfig.SubdomainBruteForceThreads)
		for _, each := range tIPs {
			if structs.GlobalConfig.AllowLocalAreaDomain && utils.IsLocalIP(each) {
				continue
			}
			ips = append(ips, each)
		}
	}
	ips = utils.RemoveDuplicateElement(ips)

	// 处理带CDN的域名，只进行https,http的探测，不进行端口扫描
	if structs.GlobalConfig.AllowCDNAssets {
		for _, cd := range cdnDomains {
			urls = append(urls, "http://"+cd)
			urls = append(urls, "https://"+cd)
		}
	}
	urls = utils.RemoveDuplicateElement(urls)

	// 端口扫描
	if len(ips) > 0 {
		if !structs.GlobalConfig.SkipHostDiscovery {
			var ICMPAlive []string
			// ICMP 探测存活
			if !structs.GlobalConfig.NoICMPPing {
				ICMPAlive = common.CheckLive(ips, false)
			}

			// TCP 探测存活
			var TCPAlive []string
			if structs.GlobalConfig.TCPPing {
				// 获取没有存活的进行探测
				var uncheck []string
				for _, ip := range ips {
					index := utils.GetItemInArray(ICMPAlive, ip)
					if index == -1 {
						uncheck = append(uncheck, ip)
					}
				}
				gologger.Info().Msg("TCP存活探测")
				common.PortScan = false
				tcpAliveIPPort := common.PortScanTCP(uncheck, "80,443,3389,445,22",
					structs.GlobalConfig.NoPortString,
					structs.GlobalConfig.TCPPortScanTimeout)
				for _, tIPPort := range tcpAliveIPPort {
					t := strings.Split(tIPPort, ":")
					TCPAlive = append(TCPAlive, t[0])
				}
			}

			ips = append(ips, ICMPAlive...)
			ips = append(ips, TCPAlive...)
			ips = utils.RemoveDuplicateElement(ips)
		}
		var tmpIPPort []string

		// 检测Masscan安装
		if structs.GlobalConfig.PortScanType == "syn" {
			if !common.CheckMasScan() {
				gologger.Error().Msg("降级TCP扫描")
				structs.GlobalConfig.PortScanType = "tcp"
			}
		}

		if structs.GlobalConfig.PortScanType == "syn" {
			// 全端口扫描
			tmpIPPort = common.PortScanSYN(ips)
		} else {
			common.PortScan = true
			tmpIPPort = common.PortScanTCP(ips, structs.GlobalConfig.Ports,
				structs.GlobalConfig.NoPortString,
				structs.GlobalConfig.TCPPortScanTimeout)
		}

		// 单个IP阈值过滤
		tmpIPPort = common.RemoveFirewall(tmpIPPort)

		for _, each := range tmpIPPort {
			ipPort = append(ipPort, each)
		}
		ipPort = utils.RemoveDuplicateElement(ipPort)
	}

	getProtocalInput := ipPort
	for _, each := range domainPort {
		getProtocalInput = append(getProtocalInput, each)
	}
	if len(getProtocalInput) > 0 {
		common.GetProtocol(getProtocalInput,
			structs.GlobalConfig.GetBannerThreads,
			structs.GlobalConfig.GetBannerTimeout)
	}

	// 获取http响应
	for hostPort, service := range structs.GlobalIPPortMap {
		if strings.Contains(service, "http") {
			urls = append(urls, "http://"+hostPort)
			urls = append(urls, "https://"+hostPort)
		}
	}
	urls = utils.RemoveDuplicateElement(urls)

	httpx.CallHTTPx(urls, http.UrlCallBack,
		structs.GlobalConfig.HTTPProxy,
		structs.GlobalConfig.WebThreads,
		structs.GlobalConfig.WebTimeout)

	// 非CDN域名 探测域名绑定资产
	// 把只允许域名访问的资产扒拉出来
	if !structs.GlobalConfig.NoHostBind {
		common.HostBindCheck()
	}

	var aliveURLs []string
	for rootURL, _ := range structs.GlobalURLMap {
		aliveURLs = append(aliveURLs, rootURL)
	}

	// 模糊搜索Yaml Poc直接打
	if structs.GlobalConfig.PocNameForSearch != "" {
		gologger.AuditTimeLogger("模糊搜索Poc: %v", structs.GlobalConfig.PocNameForSearch)
		TargetAndPocsName := make(map[string][]string)
		for _, url := range aliveURLs {
			TargetAndPocsName[url] = []string{}
		}
		report.GenerateHTMLReportHeader()

		param := callnuclei.NucleiParams{
			TargetAndPocsName: TargetAndPocsName,
			Proxy:             structs.GlobalConfig.HTTPProxy,
			CallBack:          report.AddResultByResultEvent,
			NameForSearch:     structs.GlobalConfig.PocNameForSearch,
			NoInteractsh:      structs.GlobalConfig.NoInteractsh,
			Fs:                structs.GlobalEmbedPocs,
			NP:                structs.GlobalConfig.NucleiTemplate,
			ExcludeTags:       strings.Split(structs.GlobalConfig.ExcludeTags, ","),
			Severities:        strings.Split(structs.GlobalConfig.Severities, ","),
			InteractshServer:  structs.GlobalConfig.InteractshURL,
			InteractshToken:   structs.GlobalConfig.InteractshToken,
		}
		callnuclei.CallNuclei(param)
		utils.DeleteReportWithNoResult()
		return
	}

	// 目录爆破
	if !structs.GlobalConfig.NoDirSearch {
		var checkURLs []string
		for path, _ := range structs.DirDB {
			for _, u := range aliveURLs {
				Url := ""
				if u[len(u)-1:] == "/" && path[0:1] == "/" {
					Url = u[:len(u)-1] + path
				} else {
					Url = u + path
				}
				checkURLs = append(checkURLs, Url)
			}
		}
		checkURLs = utils.RemoveDuplicateElement(checkURLs)
		gologger.Info().Msg("开始主动指纹探测")
		httpx.DirBrute(checkURLs,
			http.DirBruteCallBack,
			structs.GlobalConfig.HTTPProxy,
			structs.GlobalConfig.WebThreads,
			structs.GlobalConfig.WebTimeout)
		gologger.AuditTimeLogger("主动指纹探测结束")
	}

	ddfinger.FingerprintIdentification()

	if structs.GlobalConfig.NoPoc {
		gologger.Info().Msg("跳过漏洞探测")
		return
	}

	// 生成报告头部
	report.GenerateHTMLReportHeader()

	// 调用Nuclei
	var nucleiResults []output.ResultEvent
	TargetAndPocsName, count := http.GetPocs(structs.WorkFlowDB)
	if count > 0 {
		param := callnuclei.NucleiParams{
			TargetAndPocsName: TargetAndPocsName,
			Proxy:             structs.GlobalConfig.HTTPProxy,
			CallBack:          report.AddResultByResultEvent,
			NameForSearch:     "",
			NoInteractsh:      structs.GlobalConfig.NoInteractsh,
			Fs:                structs.GlobalEmbedPocs,
			NP:                structs.GlobalConfig.NucleiTemplate,
			ExcludeTags:       strings.Split(structs.GlobalConfig.ExcludeTags, ","),
			Severities:        strings.Split(structs.GlobalConfig.Severities, ","),
			InteractshServer:  structs.GlobalConfig.InteractshURL,
			InteractshToken:   structs.GlobalConfig.InteractshToken,
		}

		nucleiResults = callnuclei.CallNuclei(param)

	}

	// GoPoc引擎
	if !structs.GlobalConfig.NoGolangPoc {
		gopocs.GoPocsDispatcher(nucleiResults)
	}

	// 没有漏洞结果，删除生成的HTML
	utils.DeleteReportWithNoResult()

}

func searchEngine() {
	// 从Hunter中获取资产
	if structs.GlobalConfig.Hunter && !structs.GlobalConfig.Fofa {
		structs.GlobalConfig.Targets, _ = uncover.HunterSearch(structs.GlobalConfig.Targets)
		return
	}
	// 从Fofa中获取资产
	if structs.GlobalConfig.Fofa && !structs.GlobalConfig.Hunter {
		structs.GlobalConfig.Targets = uncover.FOFASearch(structs.GlobalConfig.Targets)
		return
	}
	// 从Hunter中获取资产后使用Fofa进行端口补充。
	if structs.GlobalConfig.Fofa && structs.GlobalConfig.Hunter {
		targets, tIPs := uncover.HunterSearch(structs.GlobalConfig.Targets)
		var querys []string
		for _, i := range tIPs {
			querys = append(querys, "ip=\""+i+"\"")
		}
		querys = utils.RemoveDuplicateElement(querys)
		structs.GlobalConfig.Targets = uncover.FOFASearch(querys)
		structs.GlobalConfig.Targets = append(structs.GlobalConfig.Targets, targets...)
		structs.GlobalConfig.Targets = utils.RemoveDuplicateElement(structs.GlobalConfig.Targets)
		return
	}
	// 从Quake获取资产
	if structs.GlobalConfig.Quake {
		structs.GlobalConfig.Targets = uncover.QuakeSearch(structs.GlobalConfig.Targets)
	}

}
