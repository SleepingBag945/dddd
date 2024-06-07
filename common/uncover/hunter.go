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
	"github.com/projectdiscovery/httpx/common/hashes"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"gopkg.in/yaml.v3"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type HunterResp struct {
	Code    int        `json:"code"`
	Data    hunterData `json:"data"`
	Message string     `json:"message"`
}

type infoArr struct {
	URL      string `json:"url"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
	IsWeb    string `json:"is_web"`
	City     string `json:"city"`
	Company  string `json:"company"`
	Code     int    `json:"status_code"`
	Title    string `json:"web_title"`
	Country  string `json:"country"`
	Banner   string `json:"banner"`
}

type hunterData struct {
	InfoArr   []infoArr `json:"arr"`
	Total     int       `json:"total"`
	RestQuota string    `json:"rest_quota"`
}

func getHunterKeys() []string {
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
		if sourceName == "hunter" {
			apiKeys = sourceApiKeysMap[sourceName]
			break
		}
	}
	if len(apiKeys) == 0 {
		gologger.Fatal().Msg("未获取到Hunter API Key")
		return []string{}
	}

	return apiKeys
}

// SearchHunter 从Hunter中搜索目标
func SearchHunterCore(keyword string, pageSize int, maxQueryPage int) ([]string, []string) {
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	url := "https://hunter.qianxin.com/openApi/search"
	keys := getHunterKeys()
	randKey := keys[rand.Intn(len(keys))]

	page := 1
	currentQueryCount := 0

	var results []string
	var ipResult []string
	for page <= maxQueryPage {
		req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			gologger.Fatal().Msgf("Hunter API请求构建失败。")
		}
		unc := keyword
		search := base64.URLEncoding.EncodeToString([]byte(unc))
		q := req.URL.Query()
		q.Add("search", search)
		q.Add("api-key", randKey)
		q.Add("page", fmt.Sprintf("%d", page))
		q.Add("page_size", fmt.Sprintf("%d", pageSize))
		q.Add("is_web", "3")
		req.URL.RawQuery = q.Encode()

		resp, errDo := client.Do(req)
		if errDo != nil {
			gologger.Error().Msgf("[Hunter] %s 资产查询失败！请检查网络状态。Error:%s", keyword, errDo.Error())
			time.Sleep(time.Second * 3)
			continue
		}
		defer resp.Body.Close()

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			gologger.Error().Msgf("获取Hunter 响应Body失败: %v", err.Error())
			time.Sleep(time.Second * 3)
			continue
		}

		var responseJson HunterResp
		if err = json.Unmarshal(data, &responseJson); err != nil {
			gologger.Error().Msgf("[Hunter] 返回数据Json解析失败! Error:%s", err.Error())
			time.Sleep(time.Second * 3)
			continue
		}

		if responseJson.Code != 200 {
			gologger.Error().Msgf("[Hunter] %s 搜索失败！Error:%s", keyword, responseJson.Message)

			if strings.Contains(responseJson.Message, "今日免费积分已用") ||
				strings.Contains(responseJson.Message, "今日免费积分不足") {
				time.Sleep(time.Second * 3)
				continue
			}

			if responseJson.Message == "请求太多啦，稍后再试试" {
				time.Sleep(time.Second * 3)
				continue
			}
			return results, ipResult
		}

		if responseJson.Data.Total == 0 {
			gologger.Error().Msgf("[Hunter] %s 无结果。", keyword)
			time.Sleep(time.Second * 3)
			return results, ipResult
		}

		// 做一个域名缓存，避免重复dns请求
		domainCDNMap := make(map[string]bool)
		var domainList []string

		for _, v := range responseJson.Data.InfoArr {
			domainList = append(domainList, v.Domain)
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

		for _, v := range responseJson.Data.InfoArr {
			isCDN := false
			t, ok := domainCDNMap[v.Domain]
			if ok {
				isCDN = t
			}
			if !isCDN {
				AddIPDomainMap(v.IP, v.Domain)
			}
			if v.IsWeb == "是" {
				if structs.GlobalConfig.LowPerceptionMode {
					rootURL := fmt.Sprintf("%s://%s:%d", v.Protocol, v.IP, v.Port)

					structs.GlobalURLMapLock.Lock()
					_, rootURLOK := structs.GlobalURLMap[rootURL]
					structs.GlobalURLMapLock.Unlock()
					if !rootURLOK {
						responseCode, header, body, server, contentType, contentLen := utils.ExtractResponse(v.Banner)

						md5 := hashes.Md5([]byte(body))
						headerMd5 := hashes.Md5([]byte(header))
						_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(body))
						_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(header))

						l, e := strconv.Atoi(contentLen)
						if e != nil {
							l = 0
						}

						rspc, re := strconv.Atoi(responseCode)
						if re != nil {
							rspc = 0
						}

						webPath := structs.UrlPathEntity{
							Hash:             md5,
							Title:            v.Title,
							StatusCode:       rspc,
							ContentType:      contentType,
							Server:           server,
							ContentLength:    l,
							HeaderHashString: headerMd5,
							IconHash:         "", // hunter未提供hash
						}

						urlE := structs.URLEntity{
							IP:       v.IP,
							Port:     v.Port,
							WebPaths: nil,
							Cert:     "", // hunter未提供证书信息
						}

						urlE.WebPaths = make(map[string]structs.UrlPathEntity)
						urlE.WebPaths["/"] = webPath

						structs.GlobalURLMapLock.Lock()
						structs.GlobalURLMap[rootURL] = urlE
						structs.GlobalURLMapLock.Unlock()
					}
				} else { // 正常模式
					p := ""
					if structs.GlobalConfig.OnlyIPPort && !isCDN {
						p = fmt.Sprintf("%s://%s:%d", v.Protocol, v.IP, v.Port)
					} else {
						p = v.URL
					}
					if utils.GetItemInArray(results, p) == -1 {
						if !isCDN || structs.GlobalConfig.AllowCDNAssets {
							results = append(results, p)
							// gologger.Silent().Msgf("[Hunter] [%d] %s [%s] [%s] [%s]", v.Code, p, v.Title, v.City, v.Company)
							ddout.FormatOutput(ddout.OutputMessage{
								Type:     "Hunter",
								IP:       v.IP,
								IPs:      nil,
								Port:     strconv.Itoa(v.Port),
								Protocol: v.Protocol,
								Web: ddout.WebInfo{
									Title:  v.Title,
									Status: strconv.Itoa(v.Code),
								},
								Finger:        nil,
								Domain:        v.Domain,
								GoPoc:         ddout.GoPocsResultType{},
								URI:           p,
								City:          v.City,
								AdditionalMsg: v.Company,
							})
						}
					}
				}
			} else {
				if structs.GlobalConfig.LowPerceptionMode {
					hostPort := fmt.Sprintf("%s:%d", v.IP, v.Port)
					structs.GlobalIPPortMapLock.Lock()
					_, ok := structs.GlobalIPPortMap[hostPort]
					structs.GlobalIPPortMapLock.Unlock()
					if !ok {
						structs.GlobalBannerHMap.Set(hostPort, []byte(v.Banner))
						structs.GlobalIPPortMapLock.Lock()
						structs.GlobalIPPortMap[hostPort] = v.Protocol
						structs.GlobalIPPortMapLock.Unlock()
					}
				} else {
					results = append(results, fmt.Sprintf("%s:%v", v.IP, v.Port))

					p := fmt.Sprintf("%s:%d", v.IP, v.Port)
					if utils.GetItemInArray(results, p) == -1 {
						if !isCDN || structs.GlobalConfig.AllowCDNAssets {
							results = append(results, p)
							// gologger.Silent().Msgf("[Hunter] %s://%s:%d", v.Protocol, v.IP, v.Port)
							ddout.FormatOutput(ddout.OutputMessage{
								Type:          "Hunter",
								IP:            v.IP,
								IPs:           nil,
								Port:          strconv.Itoa(v.Port),
								Protocol:      v.Protocol,
								Web:           ddout.WebInfo{},
								Finger:        nil,
								Domain:        v.Domain,
								GoPoc:         ddout.GoPocsResultType{},
								URI:           "",
								City:          v.City,
								AdditionalMsg: v.Company,
							})
						}
					}
				}
			}
			if !isCDN {
				ipResult = append(ipResult, v.IP)
			}
		}

		currentQueryCount += len(responseJson.Data.InfoArr)
		gologger.Info().Msgf("[Hunter] [%s] 当前第 [%d] 页 查询进度: %d/%d %v", keyword, page, currentQueryCount,
			responseJson.Data.Total, responseJson.Data.RestQuota)

		if currentQueryCount >= responseJson.Data.Total {
			return results, ipResult
		}

		page += 1

		// 避免请求过于频繁
		time.Sleep(time.Second * 3)

	}
	return results, ipResult
}

func HunterSearch(keywords []string) ([]string, []string) {
	gologger.Info().Msgf("准备从 Hunter 获取数据")
	gologger.AuditTimeLogger("准备从 Hunter 获取数据")
	var results []string
	var ipResults []string
	for _, keyword := range keywords {
		result, ipResult := SearchHunterCore(keyword,
			structs.GlobalConfig.HunterPageSize,
			structs.GlobalConfig.HunterMaxPageCount)
		results = append(results, result...)
		ipResults = append(ipResults, ipResult...)
	}
	return utils.RemoveDuplicateElement(results), utils.RemoveDuplicateElement(ipResults)
}
