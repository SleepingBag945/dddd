package http

import (
	"dddd/ddout"
	"dddd/lib/ddfinger"
	"dddd/structs"
	"dddd/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	"net/url"
	"strconv"
	"strings"
)

func UrlCallBack(resp runner.Result) {

	finalUrl := ""
	if resp.FinalURL != "" {
		finalUrl = resp.FinalURL
	} else {
		finalUrl = resp.URL
	}

	url := URLParse(finalUrl)
	pth := url.Path
	if pth == "" {
		pth = "/"
	}
	rootURL := fmt.Sprintf("%s://%s", url.Scheme, url.Host)
	structs.GlobalURLMapLock.Lock()
	_, rootURLOK := structs.GlobalURLMap[rootURL]
	structs.GlobalURLMapLock.Unlock()
	if rootURLOK {
		// 有这个root，查看这个path，如果没这个path再加
		structs.GlobalURLMapLock.Lock()
		_, pathOK := structs.GlobalURLMap[rootURL].WebPaths[url.Path]
		structs.GlobalURLMapLock.Unlock()
		if !pathOK {
			// 没有这个path
			md5 := resp.Hashes["body_md5"].(string)
			headerMd5 := resp.Hashes["header_md5"].(string)
			_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
			_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))
			structs.GlobalURLMapLock.Lock()
			structs.GlobalURLMap[rootURL].WebPaths[pth] = structs.UrlPathEntity{
				Hash:             md5,
				Title:            resp.Title,
				StatusCode:       resp.StatusCode,
				ContentType:      resp.ContentType,
				Server:           resp.WebServer,
				ContentLength:    resp.ContentLength,
				HeaderHashString: headerMd5,
				IconHash:         resp.FavIconMMH3,
			}
			structs.GlobalURLMapLock.Unlock()

			ddout.FormatOutput(ddout.OutputMessage{
				Type: "Web",
				IP:   "",
				Port: "",
				URI:  resp.URL,
				Web: ddout.WebInfo{
					Status: strconv.Itoa(resp.StatusCode),
					Title:  resp.Title,
				},
			})

		}
	} else {
		// 没有这个url

		port, err := strconv.Atoi(resp.Port)
		if err != nil {
			port = 0
		}

		md5 := resp.Hashes["body_md5"].(string)
		headerMd5 := resp.Hashes["header_md5"].(string)
		_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
		_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))

		webPath := structs.UrlPathEntity{
			Hash:             md5,
			Title:            resp.Title,
			StatusCode:       resp.StatusCode,
			ContentType:      resp.ContentType,
			Server:           resp.WebServer,
			ContentLength:    resp.ContentLength,
			HeaderHashString: headerMd5,
			IconHash:         resp.FavIconMMH3,
		}

		urlE := structs.URLEntity{
			IP:       resp.Host,
			Port:     port,
			WebPaths: nil,
			Cert:     getTLSString(resp),
		}

		urlE.WebPaths = make(map[string]structs.UrlPathEntity)
		urlE.WebPaths[pth] = webPath

		structs.GlobalURLMapLock.Lock()
		structs.GlobalURLMap[rootURL] = urlE
		structs.GlobalURLMapLock.Unlock()

		ddout.FormatOutput(ddout.OutputMessage{
			Type: "Web",
			IP:   "",
			Port: "",
			URI:  resp.URL,
			Web: ddout.WebInfo{
				Status: strconv.Itoa(resp.StatusCode),
				Title:  resp.Title,
			},
		})
	}

}

func getTLSString(resp runner.Result) string {
	result := ""
	if resp.TLSData == nil {
		return result
	}

	result += "SubjectCN: " + resp.TLSData.SubjectCN + "\n"
	result += "SubjectDN: " + resp.TLSData.SubjectDN + "\n"

	result += "IssuerCN: " + resp.TLSData.IssuerCN + "\n"
	result += "IssuerDN: " + resp.TLSData.IssuerDN + "\n"

	result += "IssuerOrg: \n"
	for _, v := range resp.TLSData.IssuerOrg {
		result += "    - " + v + "\n"
	}

	return result

}

func URLParse(URLRaw string) *url.URL {
	URL, _ := url.Parse(URLRaw)
	return URL
}

func AddYamlSuffix(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, ".yaml") {
		return s
	} else {
		return s + ".yaml"
	}
}

func addPocs(target string, result *map[string][]string, workflowEntity structs.WorkFlowEntity) {
	// 判断有没有加入过
	_, ok := (*result)[target]
	if !ok { // 没有添加过这个目标
		(*result)[target] = []string{}
		for _, pocName := range workflowEntity.PocsName {
			(*result)[target] = append((*result)[target], AddYamlSuffix(pocName))
			gologger.AuditLogger("    - " + pocName)
		}
	} else { // 添加过就逐个比较
		existPocNames, _ := (*result)[target]
		for _, pocName := range workflowEntity.PocsName {
			// 没有就添加
			if utils.GetItemInArray(existPocNames, pocName) == -1 {
				(*result)[target] = append((*result)[target], AddYamlSuffix(pocName))
				gologger.AuditLogger("    - " + pocName)
			}
		}
	}
}

func GetPocs(workflowDB map[string]structs.WorkFlowEntity) (map[string][]string, int) {
	gologger.AuditTimeLogger("根据指纹选择Poc")
	result := make(map[string][]string)
	count := 0

	var generalKeys []string
	if !structs.GlobalConfig.DisableGeneralPoc {
		for k, workflowEntity := range workflowDB {
			if strings.Contains(k, "General-Poc-") {
				if len(workflowEntity.PocsName) == 0 {
					continue
				}
				generalKeys = append(generalKeys, k)
			}
		}
	}

	for target, fingerprints := range structs.GlobalResultMap {
		gologger.AuditLogger(target + ":")
		for _, finger := range fingerprints {
			workflowEntity, ok := workflowDB[finger]
			if !ok || len(workflowEntity.PocsName) == 0 {
				continue
			}

			if !strings.Contains(target, "http") {
				if !workflowEntity.RootType { // 与Root无关
					continue
				}
				addPocs(target, &result, workflowEntity)
				count++
			} else {
				Url := URLParse(target)

				// Web
				if workflowEntity.RootType {
					rootURL := fmt.Sprintf("%s://%s", Url.Scheme, Url.Host)
					addPocs(rootURL, &result, workflowEntity)
					count++

				}

				if (Url.Path != "/" && Url.Path != "") && workflowEntity.BaseType {
					addPocs(target, &result, workflowEntity)
					count++
				}

				if (Url.Path != "/" && Url.Path != "") && workflowEntity.DirType {
					splitPath := strings.Split(Url.Path, "/")
					for i := 1; i < len(splitPath); i++ {
						newPath := strings.Join(splitPath[:i], "/")
						t := fmt.Sprintf("%s://%s%s", Url.Scheme, Url.Host, newPath)
						addPocs(t, &result, workflowEntity)
						count++
					}

				}
			}

		}

		for _, key := range generalKeys {
			workflowEntity, ok := workflowDB[key]
			if !ok || len(workflowEntity.PocsName) == 0 {
				continue
			}

			if !strings.Contains(target, "http") {
				if !workflowEntity.RootType { // 与Root无关
					continue
				}
				addPocs(target, &result, workflowEntity)
				count++
			} else {
				Url := URLParse(target)

				// Web
				if workflowEntity.RootType {
					rootURL := fmt.Sprintf("%s://%s", Url.Scheme, Url.Host)
					addPocs(rootURL, &result, workflowEntity)
					count++
				}

				if (Url.Path != "/" && Url.Path != "") && workflowEntity.BaseType {
					addPocs(target, &result, workflowEntity)
					count++
				}

				if (Url.Path != "/" && Url.Path != "") && workflowEntity.DirType {
					splitPath := strings.Split(Url.Path, "/")
					for i := 1; i < len(splitPath); i++ {
						newPath := strings.Join(splitPath[:i], "/")
						t := fmt.Sprintf("%s://%s%s", Url.Scheme, Url.Host, newPath)
						addPocs(t, &result, workflowEntity)
						count++
					}

				}
			}
		}

	}
	return result, count
}

func DirBruteCallBack(resp runner.Result) {
	var Paths []string
	for dbPath, _ := range structs.DirDB {
		if strings.HasSuffix(resp.Path, dbPath) {
			Paths = append(Paths, dbPath)
		}
	}

	for _, path := range Paths {
		productNames := structs.DirDB[path]
		for _, productName := range productNames {
			success := false
			for _, v := range structs.FingerprintDB {
				if success {
					break
				}
				if v.ProductName == productName {
					portInt, err := strconv.Atoi(resp.Port)
					if err != nil {
						portInt = -1
					}
					r := ddfinger.SingleCheck(v, resp.Scheme, resp.Header, resp.Body, resp.WebServer, resp.Title, getTLSString(resp),
						portInt, resp.Path, "0", "0", resp.StatusCode, resp.ContentType, "")
					// 满足这个products的要求
					if r {
						success = true
						// 给对应的urlEntry添加指纹
						Url := URLParse(resp.URL)
						rootURL := fmt.Sprintf("%s://%s", Url.Scheme, Url.Host)

						structs.GlobalURLMapLock.Lock()
						_, rootURLOk := structs.GlobalURLMap[rootURL]
						structs.GlobalURLMapLock.Unlock()
						if rootURLOk {
							// 如果爆破来源上一步验活，那这里必然存在rootURL.
							// 有这个root，查看这个path，如果没这个path再加
							structs.GlobalURLMapLock.Lock()
							_, pathOK := structs.GlobalURLMap[rootURL].WebPaths[Url.Path]
							structs.GlobalURLMapLock.Unlock()
							if !pathOK {
								// 没有这个path
								md5 := resp.Hashes["body_md5"].(string)
								headerMd5 := resp.Hashes["header_md5"].(string)
								_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
								_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))
								structs.GlobalURLMapLock.Lock()
								structs.GlobalURLMap[rootURL].WebPaths[Url.Path] = structs.UrlPathEntity{
									Hash:             md5,
									Title:            resp.Title,
									StatusCode:       resp.StatusCode,
									ContentType:      resp.ContentType,
									Server:           resp.WebServer,
									ContentLength:    resp.ContentLength,
									HeaderHashString: headerMd5,
									IconHash:         resp.FavIconMMH3,
								}
								structs.GlobalURLMapLock.Unlock()
							}

							ddout.FormatOutput(ddout.OutputMessage{
								Type:          "Active-Finger",
								IP:            "",
								IPs:           nil,
								Port:          "",
								Protocol:      "",
								Web:           ddout.WebInfo{},
								Finger:        []string{productName},
								Domain:        "",
								GoPoc:         ddout.GoPocsResultType{},
								URI:           resp.URL,
								AdditionalMsg: "",
							})
							// gologger.Silent().Msgf("[Active-Finger] %s [%s]", resp.URL, productName)
						}
					}
				}
			}
		}
	}
}

func HostBindHTTPxCallBack(resp runner.Result) {
	ips := resp.A
	path := resp.Path
	newWeb := false
	for _, ip := range ips {
		structs.GlobalURLMapLock.Lock()
		for rootURL, urlEntry := range structs.GlobalURLMap {
			URL, err := url.Parse(rootURL)
			if err != nil {
				continue
			}
			if URL.Scheme != resp.Scheme {
				continue
			}
			if urlEntry.IP != ip {
				continue
			}
			port := strconv.Itoa(urlEntry.Port)
			if port != resp.Port {
				continue
			}

			existPath, ok := urlEntry.WebPaths[path]
			if !ok {
				continue
			}

			if existPath.StatusCode != resp.StatusCode || existPath.Hash != existPath.Hash {
				newWeb = true
			}

		}
		structs.GlobalURLMapLock.Unlock()
	}

	if !newWeb {
		return
	}

	ddout.FormatOutput(ddout.OutputMessage{
		Type:     "Domain-Bind",
		IP:       "",
		IPs:      nil,
		Port:     "",
		Protocol: "",
		Web: ddout.WebInfo{
			Status: strconv.Itoa(resp.StatusCode),
		},
		Finger:        nil,
		Domain:        "",
		GoPoc:         ddout.GoPocsResultType{},
		URI:           resp.URL,
		AdditionalMsg: resp.Title,
	})

	//if resp.Title != "" {
	//	gologger.Silent().Msgf("[Domain-Bind] [%v] %v [%v]", resp.StatusCode, resp.URL, resp.Title)
	//} else {
	//	gologger.Silent().Msgf("[Domain-Bind] [%v] %v", resp.StatusCode, resp.URL)
	//}

	finalUrl := ""
	if resp.FinalURL != "" {
		finalUrl = resp.FinalURL
	} else {
		finalUrl = resp.URL
	}

	urlFinal := URLParse(finalUrl)
	rootURL := fmt.Sprintf("%s://%s", urlFinal.Scheme, urlFinal.Host)
	structs.GlobalURLMapLock.Lock()
	_, rootURLOK := structs.GlobalURLMap[rootURL]
	structs.GlobalURLMapLock.Unlock()
	if rootURLOK {
		// 有这个root，查看这个path，如果没这个path再加
		structs.GlobalURLMapLock.Lock()
		_, pathOK := structs.GlobalURLMap[rootURL].WebPaths[urlFinal.Path]
		structs.GlobalURLMapLock.Unlock()
		if !pathOK {
			// 没有这个path
			md5 := resp.Hashes["body_md5"].(string)
			headerMd5 := resp.Hashes["header_md5"].(string)
			_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
			_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))
			structs.GlobalURLMapLock.Lock()
			structs.GlobalURLMap[rootURL].WebPaths[urlFinal.Path] = structs.UrlPathEntity{
				Hash:             md5,
				Title:            resp.Title,
				StatusCode:       resp.StatusCode,
				ContentType:      resp.ContentType,
				Server:           resp.WebServer,
				ContentLength:    resp.ContentLength,
				HeaderHashString: headerMd5,
				IconHash:         resp.FavIconMMH3,
			}
			structs.GlobalURLMapLock.Unlock()
		}
	} else {
		// 没有这个url

		port, err := strconv.Atoi(resp.Port)
		if err != nil {
			port = 0
		}

		md5 := resp.Hashes["body_md5"].(string)
		headerMd5 := resp.Hashes["header_md5"].(string)
		_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
		_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))

		webPath := structs.UrlPathEntity{
			Hash:             md5,
			Title:            resp.Title,
			StatusCode:       resp.StatusCode,
			ContentType:      resp.ContentType,
			Server:           resp.WebServer,
			ContentLength:    resp.ContentLength,
			HeaderHashString: headerMd5,
			IconHash:         resp.FavIconMMH3,
		}

		urlE := structs.URLEntity{
			IP:       resp.Host,
			Port:     port,
			WebPaths: nil,
			Cert:     getTLSString(resp),
		}

		urlE.WebPaths = make(map[string]structs.UrlPathEntity)
		urlE.WebPaths[urlFinal.Path] = webPath

		structs.GlobalURLMapLock.Lock()
		structs.GlobalURLMap[rootURL] = urlE
		structs.GlobalURLMapLock.Unlock()
	}

}
