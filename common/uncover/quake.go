package uncover

import (
	"dddd/ddout"
	"dddd/structs"
	"dddd/utils"
	"dddd/utils/cdn"
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
	"strconv"
	"strings"
	"time"
)

var IsVIP bool

type QuakeServiceInfo struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		Time      time.Time `json:"time"`
		Transport string    `json:"transport"`
		Service   struct {
			HTTP struct {
				HTMLHash string `json:"html_hash"`
				Favicon  struct {
					Hash     string `json:"hash"`
					Location string `json:"location"`
					Data     string `json:"data"`
				} `json:"favicon"`
				Robots          string   `json:"robots"`
				SitemapHash     string   `json:"sitemap_hash"`
				Server          string   `json:"server"`
				Body            string   `json:"body"`
				XPoweredBy      string   `json:"x_powered_by"`
				MetaKeywords    string   `json:"meta_keywords"`
				RobotsHash      string   `json:"robots_hash"`
				Sitemap         string   `json:"sitemap"`
				Path            string   `json:"path"`
				Title           string   `json:"title"`
				Host            string   `json:"host"`
				SecurityText    string   `json:"security_text"`
				StatusCode      int      `json:"status_code"`
				ResponseHeaders string   `json:"response_headers"`
				URL             []string `json:"http_load_url"`
			} `json:"http"`
			Version  string `json:"version"`
			Name     string `json:"name"`
			Product  string `json:"product"`
			Banner   string `json:"banner"`
			Response string `json:"response"`
		} `json:"service"`
		Images     []interface{} `json:"images"`
		OsName     string        `json:"os_name"`
		Components []interface{} `json:"components"`
		Location   struct {
			DistrictCn  string    `json:"district_cn"`
			ProvinceCn  string    `json:"province_cn"`
			Gps         []float64 `json:"gps"`
			ProvinceEn  string    `json:"province_en"`
			CityEn      string    `json:"city_en"`
			CountryCode string    `json:"country_code"`
			CountryEn   string    `json:"country_en"`
			Radius      float64   `json:"radius"`
			DistrictEn  string    `json:"district_en"`
			Isp         string    `json:"isp"`
			StreetEn    string    `json:"street_en"`
			Owner       string    `json:"owner"`
			CityCn      string    `json:"city_cn"`
			CountryCn   string    `json:"country_cn"`
			StreetCn    string    `json:"street_cn"`
		} `json:"location"`
		Asn       int    `json:"asn"`
		Hostname  string `json:"hostname"`
		Org       string `json:"org"`
		OsVersion string `json:"os_version"`
		IsIpv6    bool   `json:"is_ipv6"`
		IP        string `json:"ip"`
		Port      int    `json:"port"`
	} `json:"data"`
	Meta struct {
		Total        int    `json:"total"`
		PaginationID string `json:"pagination_id"`
	} `json:"meta"`
}

func getQuakeKeys() []string {
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
		if sourceName == "quake" {
			apiKeys = sourceApiKeysMap[sourceName]
			break
		}
	}
	if len(apiKeys) == 0 {
		gologger.Fatal().Msg("未获取到Quake API Key")
		return []string{}
	}

	return apiKeys
}

// 从Fofa中搜索目标
func SearchQuakeCore(keyword string, pageSize int) []string {
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	url := "https://quake.360.net/api/v3/search/quake_service"
	keys := getQuakeKeys()
	randKey := keys[rand.Intn(len(keys))]

	data := make(map[string]interface{})
	data["query"] = keyword
	data["start"] = "0"
	data["size"] = strconv.Itoa(pageSize)
	if !IsVIP {
		data["include"] = []string{"ip", "port"}
	}
	jsonData, _ := json.Marshal(data)

	req, err := retryablehttp.NewRequest(http.MethodPost, url, jsonData)
	if err != nil {
		gologger.Fatal().Msgf("Quake API请求构建失败。")
	}
	req.Header.Set("X-QuakeToken", randKey)
	req.Header.Set("Content-Type", "application/json")

	// 确保不会超速
	time.Sleep(time.Second * 2)
	var results []string

	resp, errDo := client.Do(req)
	if errDo != nil {
		gologger.Error().Msgf("[Quake] [%s] 资产查询失败！请检查网络状态。Error:%s", keyword, errDo.Error())
		return results
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		gologger.Fatal().Msgf("[Quake] API-KEY错误。请检查。")
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msgf("[Quake] 获取Hunter 响应Body失败: %v", err.Error())
		return results
	}

	var serviceInfo QuakeServiceInfo
	err = json.Unmarshal(respBody, &serviceInfo)
	if err != nil {
		gologger.Error().Msg("[Quake] 响应解析失败，疑似Token失效、。Quake接口具体返回信息如下：")
		fmt.Println(string(respBody))
		return results
	}

	// 做一个域名缓存，避免重复dns请求
	domainCDNMap := make(map[string]bool)
	var domainList []string

	for _, d := range serviceInfo.Data {
		domainList = append(domainList, d.Service.HTTP.Host)
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

	for _, d := range serviceInfo.Data {
		if d.Service.HTTP.URL == nil {
			t := fmt.Sprintf("%s:%d", d.IP, d.Port)
			if utils.GetItemInArray(results, t) == -1 {
				ddout.FormatOutput(ddout.OutputMessage{
					Type:          "Quake",
					IP:            d.IP,
					IPs:           nil,
					Port:          strconv.Itoa(d.Port),
					Protocol:      "",
					Web:           ddout.WebInfo{},
					Finger:        nil,
					Domain:        "",
					GoPoc:         ddout.GoPocsResultType{},
					URI:           "",
					City:          "",
					Show:          t,
					AdditionalMsg: "",
				})
				// gologger.Silent().Msgf("[Quake] %s", t)
				results = append(results, t)
			}
		} else {
			isCDN := false
			t, ok := domainCDNMap[d.Service.HTTP.Host]
			if ok {
				isCDN = t
			}
			if !isCDN {
				AddIPDomainMap(d.IP, d.Service.HTTP.Host)
			}

			if structs.GlobalConfig.OnlyIPPort && !isCDN {
				u := fmt.Sprintf("%v://%v:%v", strings.ReplaceAll(d.Service.Name, "http/ssl", "https"), d.IP, d.Port)
				if utils.GetItemInArray(results, u) == -1 {
					results = append(results, u)
					// gologger.Silent().Msgf("[Quake] %s", u)
					ddout.FormatOutput(ddout.OutputMessage{
						Type:          "Quake",
						IP:            d.IP,
						IPs:           nil,
						Port:          strconv.Itoa(d.Port),
						Protocol:      d.Service.Name,
						Web:           ddout.WebInfo{},
						Finger:        nil,
						Domain:        "",
						GoPoc:         ddout.GoPocsResultType{},
						URI:           "",
						City:          "",
						Show:          u,
						AdditionalMsg: "",
					})
				}
			} else {
				for _, u := range d.Service.HTTP.URL {
					if utils.GetItemInArray(results, u) == -1 {
						if !isCDN || structs.GlobalConfig.AllowCDNAssets {
							// gologger.Silent().Msgf("[Quake] %s", u)
							ddout.FormatOutput(ddout.OutputMessage{
								Type:          "Quake",
								IP:            d.IP,
								IPs:           nil,
								Port:          strconv.Itoa(d.Port),
								Protocol:      d.Service.Name,
								Web:           ddout.WebInfo{},
								Finger:        nil,
								Domain:        "",
								GoPoc:         ddout.GoPocsResultType{},
								URI:           u,
								City:          "",
								Show:          u,
								AdditionalMsg: "",
							})
							results = append(results, u)
						}
					}
				}
			}
		}

	}
	return results
}

func IsQuakeVIP() bool {
	keys := getQuakeKeys()
	randKey := keys[rand.Intn(len(keys))]
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	url := "https://quake.360.net/api/v3/user/info"

	req, err := retryablehttp.NewRequest(http.MethodGet, url, "")
	if err != nil {
		gologger.Fatal().Msgf("Quake API请求构建失败。")
	}
	req.Header.Set("X-QuakeToken", randKey)
	req.Header.Set("Content-Type", "application/json")
	resp, errDo := client.Do(req)
	if errDo != nil {
		gologger.Error().Msgf("[Quake] 用户信息查询失败！请检查网络状态。Error:%s", errDo.Error())
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		gologger.Fatal().Msgf("[Quake] API-KEY错误。请检查。")
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msgf("[Quake] 获取Hunter 响应Body失败: %v", err.Error())
		return false
	}

	if strings.Contains(string(respBody), "终身会员") {
		return true
	}
	if strings.Contains(string(respBody), "高级会员") {
		return true
	}

	return false
}

func QuakeSearch(keywords []string) []string {
	IsVIP = false
	gologger.Info().Msg("正在查询Quake账户权限。")
	IsVIP = IsQuakeVIP()
	if IsVIP {
		gologger.Info().Msgf("VIP")
	} else {
		gologger.Info().Msgf("非VIP")
	}
	gologger.Info().Msgf("准备从 Quake 获取数据")
	var results []string
	for _, keyword := range keywords {
		result := SearchQuakeCore(keyword,
			structs.GlobalConfig.QuakeSize)
		results = append(results, result...)
	}
	return utils.RemoveDuplicateElement(results)
}
