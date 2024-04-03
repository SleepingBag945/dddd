package uncover

import (
	"dddd/ddout"
	"dddd/structs"
	"dddd/utils"
	"dddd/utils/cdn"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"gopkg.in/yaml.v3"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

type FOFAResponseJson struct {
	Error   bool       `json:"error"`
	Mode    string     `json:"mode"`
	Page    int        `json:"page"`
	Query   string     `json:"query"`
	Results [][]string `json:"results"`
	Size    int        `json:"size"`
}

func getFOFAKeys() []string {
	var apiKeys []string
	f, err := os.Open(structs.GlobalConfig.APIConfigFilePath)
	if err != nil {
		gologger.Fatal().Msgf("打开API Key配置文件 %v 失败", structs.GlobalConfig.APIConfigFilePath)
		return []string{}
	}
	defer f.Close()

	sourceApiKeysMap := map[string][]string{}
	err = yaml.NewDecoder(f).Decode(sourceApiKeysMap)
	for _, source := range passive.AllSources {
		sourceName := strings.ToLower(source.Name())
		if sourceName == "fofa" {
			apiKeys = sourceApiKeysMap[sourceName]
			break
		}
	}
	if len(apiKeys) == 0 {
		gologger.Fatal().Msg("未获取到FOFA API Key")
		return []string{}
	}

	return apiKeys
}

// 从Fofa中搜索目标
func SearchFOFACore(keyword string, pageSize int) []string {
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	url := "https://fofa.info/api/v1/search/all"
	keys := getFOFAKeys()
	randKey := keys[rand.Intn(len(keys))]
	if !strings.Contains(randKey, ":") {
		gologger.Fatal().Msg("请核对FOFA API KEY格式。正确格式为: email:key")
	}
	tmp := strings.Split(randKey, ":")
	email := tmp[0]
	key := tmp[1]

	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		gologger.Fatal().Msgf("FOFA API请求构建失败。")
	}
	unc := keyword
	search := base64.StdEncoding.EncodeToString([]byte(unc))
	q := req.URL.Query()
	q.Add("qbase64", search)
	q.Add("email", email)
	q.Add("key", key)
	q.Add("page", "1")
	q.Add("size", fmt.Sprintf("%d", pageSize))
	q.Add("fields", "host,protocol,title,icp,ip,port,domain")

	q.Add("full", "false")
	req.URL.RawQuery = q.Encode()

	// 确保不会超速
	time.Sleep(time.Second * 3)
	var results []string

	resp, errDo := client.Do(req)
	if errDo != nil {
		gologger.Error().Msgf("[Fofa] [%s] 资产查询失败！请检查网络状态。Error:%s", keyword, errDo.Error())
		return results
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msgf("[Fofa] 获取Hunter 响应Body失败: %v", err.Error())
		return results
	}

	var responseJson FOFAResponseJson
	if err = json.Unmarshal(data, &responseJson); err != nil {
		gologger.Error().Msgf("[Fofa] 返回数据Json解析失败! Error:%s", err.Error())
		return results
	}

	if responseJson.Error {
		gologger.Error().Msgf("[Fofa] [%s] 搜索失败！返回响应体Error为True。返回信息: %v", keyword, string(data))
		return results
	}

	if responseJson.Size == 0 {
		gologger.Error().Msgf("[Fofa] [%s] 无结果。", keyword)
		return results
	}

	// 做一个域名缓存，避免重复dns请求
	domainCDNMap := make(map[string]bool)
	var domainList []string
	for _, result := range responseJson.Results {
		host := result[0]
		protocol := result[1]
		port := result[5]
		domain := ""
		if result[6] != "" {
			realHost := strings.ReplaceAll(host, protocol+"://", "")
			domain = strings.ReplaceAll(realHost, ":"+port, "")
		}
		domainList = append(domainList, domain)
	}
	domainList = utils.RemoveDuplicateElement(domainList)
	if len(domainList) != 0 {
		gologger.Info().Msgf("正在查询 [%v] 个域名是否为CDN资产", len(domainList))
	}
	cdnDomains, normalDomains, _ := cdn.CheckCDNs(domainList, structs.GlobalConfig.SubdomainBruteForceThreads)
	for _, d := range cdnDomains {
		_, ok := domainCDNMap[d]
		if !ok {
			domainCDNMap[d] = true
		}
	}
	for _, d := range normalDomains {
		_, ok := domainCDNMap[d]
		if !ok {
			domainCDNMap[d] = false
		}
	}

	for _, result := range responseJson.Results {
		host := result[0]
		protocol := result[1]
		icp := result[2]
		title := result[3]
		ip := result[4]
		port := result[5]
		domain := ""
		if result[6] != "" {
			realHost := strings.ReplaceAll(host, protocol+"://", "")
			domain = strings.ReplaceAll(realHost, ":"+port, "")
		}

		isCDN := false
		if domain != "" {
			domainInfo, ok := domainCDNMap[domain]
			if ok {
				isCDN = domainInfo
			}
			if !isCDN {
				AddIPDomainMap(ip, domain)
			}

		}

		show := "[Fofa]"
		addTarget := ""
		if structs.GlobalConfig.OnlyIPPort && !isCDN {
			if protocol == "http" || protocol == "https" {
				addTarget = protocol + "://" + ip + ":" + port
				show += " " + addTarget
			} else {
				addTarget = protocol + "://" + ip + ":" + port
				show += " " + addTarget
			}
		} else {
			if protocol == "http" {
				addTarget = protocol + "://" + host
				show += " " + addTarget
			} else if protocol == "https" {
				addTarget = host
				show += " " + host
			} else {
				addTarget = host
				show += " " + protocol + "://" + host
			}
		}

		if title != "" {
			show += " [" + title + "]"
		}
		if icp != "" {
			icp += " [" + icp + "]"
		}
		if isCDN {
			show += " [CDN]"
		}

		if utils.GetItemInArray(results, addTarget) == -1 {
			if !isCDN || structs.GlobalConfig.AllowCDNAssets {
				results = append(results, addTarget)
			}
			// gologger.Silent().Msg(show)
			ddout.FormatOutput(ddout.OutputMessage{
				Type:          "Fofa",
				IP:            ip,
				IPs:           nil,
				Port:          port,
				Protocol:      protocol,
				Web:           ddout.WebInfo{},
				Finger:        nil,
				Domain:        domain,
				GoPoc:         ddout.GoPocsResultType{},
				URI:           host,
				City:          "",
				Show:          show,
				AdditionalMsg: "",
			})
		}

	}

	gologger.Info().Msgf("[Fofa] [%s] 已查询: %d/%d", keyword, len(responseJson.Results), responseJson.Size)

	return results
}

func FOFASearch(keywords []string) []string {
	gologger.Info().Msgf("准备从 Fofa 获取数据")
	var results []string
	for _, keyword := range keywords {
		result := SearchFOFACore(keyword,
			structs.GlobalConfig.FofaMaxCount)
		results = append(results, result...)
	}
	return utils.RemoveDuplicateElement(results)
}
