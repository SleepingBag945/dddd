package uncover

import (
	"dddd/structs"
	"dddd/utils"
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
				Robots          string `json:"robots"`
				SitemapHash     string `json:"sitemap_hash"`
				Server          string `json:"server"`
				Body            string `json:"body"`
				XPoweredBy      string `json:"x_powered_by"`
				MetaKeywords    string `json:"meta_keywords"`
				RobotsHash      string `json:"robots_hash"`
				Sitemap         string `json:"sitemap"`
				Path            string `json:"path"`
				Title           string `json:"title"`
				Host            string `json:"host"`
				SecurityText    string `json:"security_text"`
				StatusCode      int    `json:"status_code"`
				ResponseHeaders string `json:"response_headers"`
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
	f, err := os.Open("config/subfinder-config.yaml")
	if err != nil {
		gologger.Fatal().Msg("打开API Key配置文件config/subfinder-config.yaml失败")
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
	data["include"] = []string{"ip", "port"}
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
		gologger.Error().Msg("[Quake] 响应解析失败，疑似Quake Token失效。")
		return results
	}

	for _, d := range serviceInfo.Data {
		t := fmt.Sprintf("%s:%d", d.IP, d.Port)
		if utils.GetItemInArray(results, t) == -1 {
			gologger.Silent().Msgf("[Quake] %s", t)
			results = append(results, t)
		}
	}
	return results
}

func QuakeSearch(keywords []string) []string {
	gologger.Info().Msgf("准备从 Quake 获取数据")
	var results []string
	for _, keyword := range keywords {
		result := SearchQuakeCore(keyword,
			structs.GlobalConfig.QuakeSize)
		results = append(results, result...)
	}
	return utils.RemoveDuplicateElement(results)
}
