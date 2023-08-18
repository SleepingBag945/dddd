package uncover

import (
	"dddd/structs"
	"dddd/utils"
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

// SearchHunter 从Hunter中搜索目标
func SearchFOFACore(keyword string, pageSize int) []string {
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	url := "https://fofa.info/api/v1/search/all"
	keys := getFOFAKeys()
	randKey := keys[rand.Intn(len(keys))]
	tmp := strings.Split(randKey, ":")
	email := tmp[0]
	key := tmp[1]

	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		gologger.Fatal().Msgf("FOFA API请求构建失败。")
	}
	unc := keyword
	search := base64.URLEncoding.EncodeToString([]byte(unc))
	q := req.URL.Query()
	q.Add("qbase64", search)
	q.Add("email", email)
	q.Add("key", key)
	q.Add("page", "1")
	q.Add("size", fmt.Sprintf("%d", pageSize))
	q.Add("fields", "host,protocol,title,icp")
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
		gologger.Error().Msgf("[Fofa] [%s] 搜索失败！返回响应体Error为True。", keyword)
		return results
	}

	if responseJson.Size == 0 {
		gologger.Error().Msgf("[Fofa] [%s] 无结果。", keyword)
		return results
	}

	for _, result := range responseJson.Results {
		host := result[0]
		protocol := result[1]
		icp := result[2]
		title := result[3]

		show := "[Fofa]"
		if protocol == "http" {
			URL := protocol + "://" + host
			results = append(results, URL)
			show += " " + URL
		} else if protocol == "https" {
			results = append(results, host)
			show += " " + host
		} else {
			results = append(results, host)
			show += " " + protocol + "://" + host
		}
		if title != "" {
			show += " [" + title + "]"
		}
		if icp != "" {
			icp += " [" + icp + "]"
		}
		gologger.Silent().Msg(show)
	}

	gologger.Info().Msgf("[Fofa] [%s] 已查询: %d/%d", keyword, len(responseJson.Results), responseJson.Size)

	return results
}

func FOFASearch(keywords []string) []string {
	var results []string
	for _, keyword := range keywords {
		result := SearchFOFACore(keyword,
			structs.GlobalConfig.FofaMaxCount)
		results = append(results, result...)
	}
	return utils.RemoveDuplicateElement(results)
}
