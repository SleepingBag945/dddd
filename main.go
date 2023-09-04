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
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"os"
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

	// 从Hunter中获取资产
	if structs.GlobalConfig.Hunter && !structs.GlobalConfig.Fofa {
		gologger.Info().Msgf("准备从 Hunter 获取数据")
		structs.GlobalConfig.Targets = uncover.HunterSearch(structs.GlobalConfig.Targets)
	}
	if structs.GlobalConfig.Fofa && !structs.GlobalConfig.Hunter {
		gologger.Info().Msgf("准备从 Fofa 获取数据")
		structs.GlobalConfig.Targets = uncover.FOFASearch(structs.GlobalConfig.Targets)
	}

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
	for _, cd := range cdnDomains {
		urls = append(urls, "http://"+cd)
		urls = append(urls, "https://"+cd)
	}
	urls = utils.RemoveDuplicateElement(urls)

	// 端口扫描
	if len(ips) > 0 {
		if !structs.GlobalConfig.SkipHostDiscovery {
			ips = common.CheckLive(ips, false)
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
			tmpIPPort = common.PortScanTCP(ips, structs.GlobalConfig.Ports,
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
		common.GetProtocol(getProtocalInput, structs.GlobalConfig.GetBannerThreads)
	}

	// 获取http响应
	for hostPort, service := range structs.GlobalIPPortMap {
		if service == "http" {
			urls = append(urls, "http://"+hostPort)
		} else if service == "https" {
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
	common.HostBindCheck()

	var aliveURLs []string
	for rootURL, _ := range structs.GlobalURLMap {
		aliveURLs = append(aliveURLs, rootURL)
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
	}

	ddfinger.FingerprintIdentification()

	// 生成报告头部
	report.GenerateHTMLReportHeader()

	// 调用Nuclei
	var nucleiResults []output.ResultEvent
	TargetAndPocsName, count := http.GetPocs(structs.WorkFlowDB)
	if count > 0 {
		nucleiResults = callnuclei.CallNuclei(TargetAndPocsName,
			structs.GlobalConfig.HTTPProxy,
			report.AddResultByResultEvent)
	}

	// GoPoc引擎
	if !structs.GlobalConfig.NoGolangPoc {
		gopocs.GoPocsDispatcher(nucleiResults)
	}

	// 没有漏洞结果，删除生成的HTML
	fileInfo, err := os.Stat(structs.GlobalConfig.ReportName)
	if err == nil {
		fileSize := fileInfo.Size()
		// 简单粗暴判断文件大小
		if fileSize < 99360 {
			_ = os.Remove(structs.GlobalConfig.ReportName)
		}
	}
}
