package ddfinger

import (
	"container/list"
	"dddd/ddout"
	"dddd/structs"
	"dddd/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// 判断优先级 非运算符返回0
func advance(ch int) int {
	// !
	if ch == 33 {
		return 3
	}
	// &
	if ch == 38 {
		return 2
	}
	// |
	if ch == 124 {
		return 1
	}
	return 0
}

// 计算纯bool表达式，支持 ! && & || | ( )
func boolEval(expression string) bool {
	// 左右括号数量相等
	if strings.Count(expression, "(") != strings.Count(expression, ")") {
		gologger.Fatal().Msg(fmt.Sprintf("[-] 纯布尔表达式 [%s] 左右括号不匹配", expression))
	}
	// 去除空格
	for strings.Contains(expression, " ") {
		expression = strings.ReplaceAll(expression, " ", "")
	}
	// 去除空表达式
	for strings.Contains(expression, "()") {
		expression = strings.ReplaceAll(expression, "()", "")
	}
	for strings.Contains(expression, "&&") {
		expression = strings.ReplaceAll(expression, "&&", "&")
	}
	for strings.Contains(expression, "||") {
		expression = strings.ReplaceAll(expression, "||", "|")
	}
	if !strings.Contains(expression, "T") && !strings.Contains(expression, "F") {
		return false
		// panic("纯布尔表达式错误，没有包含T/F")
	}

	expr := list.New()
	operator_stack := list.New()
	for _, ch := range expression {
		// ch 为 T或者F
		if ch == 84 || ch == 70 {
			expr.PushBack(int(ch))
		} else if advance(int(ch)) > 0 {
			if operator_stack.Len() == 0 {
				operator_stack.PushBack(int(ch))
				continue
			}
			// 两个!抵消
			if ch == 33 && operator_stack.Back().Value.(int) == 33 {
				operator_stack.Remove(operator_stack.Back())
				continue
			}
			for operator_stack.Len() != 0 && operator_stack.Back().Value.(int) != 40 && advance(operator_stack.Back().Value.(int)) >= advance(int(ch)) {
				e := operator_stack.Back()
				expr.PushBack(e.Value.(int))
				operator_stack.Remove(e)
			}
			operator_stack.PushBack(int(ch))

		} else if ch == 40 {
			operator_stack.PushBack(int(ch))
		} else if ch == 41 {
			for operator_stack.Back().Value.(int) != 40 {
				e := operator_stack.Back()
				expr.PushBack(e.Value.(int))
				operator_stack.Remove(e)
			}
			operator_stack.Remove(operator_stack.Back())
		}
	}
	for operator_stack.Len() != 0 {
		e := operator_stack.Back()
		expr.PushBack(e.Value.(int))
		operator_stack.Remove(e)
	}

	tf_stack := list.New()
	for expr.Len() != 0 {
		e := expr.Front()
		ch := e.Value.(int)
		expr.Remove(e)
		if ch == 84 || ch == 70 {
			tf_stack.PushBack(int(ch))
		}
		if ch == 38 { // &
			em := tf_stack.Back()
			a := em.Value.(int)
			tf_stack.Remove(em)
			em = tf_stack.Back()
			b := em.Value.(int)
			tf_stack.Remove(em)
			if a == 84 && b == 84 {
				tf_stack.PushBack(84)
			} else {
				tf_stack.PushBack(70)
			}
		}
		if ch == 124 { // |
			em := tf_stack.Back()
			a := em.Value.(int)
			tf_stack.Remove(em)
			em = tf_stack.Back()
			b := em.Value.(int)
			tf_stack.Remove(em)
			if a == 70 && b == 70 {
				tf_stack.PushBack(70)
			} else {
				tf_stack.PushBack(84)
			}
		}
		if ch == 33 { // !
			em := tf_stack.Back()
			a := em.Value.(int)
			tf_stack.Remove(em)
			if a == 70 {
				tf_stack.PushBack(84)
			} else if a == 84 {
				tf_stack.PushBack(70)
			}
		}
	}
	if tf_stack.Front().Value.(int) == 84 {
		return true
	} else {
		return false
	}

}

func getRuleData(rule string) structs.RuleData {
	if !strings.Contains(rule, "=\"") {
		return structs.RuleData{}
	}
	pos := strings.Index(rule, "=\"")
	op := 0
	if rule[pos-1] == 33 {
		op = 1
	} else if rule[pos-1] == 61 {
		op = 2
	} else if rule[pos-1] == 62 {
		op = 3
	} else if rule[pos-1] == 60 {
		op = 4
	} else if rule[pos-1] == 126 {
		op = 5
	}

	start := 0
	ti := 0
	if op > 0 {
		ti = 1
	}
	for i := pos - 1 - ti; i >= 0; i-- {
		if (rule[i] > 122 || rule[i] < 97) && rule[i] != 95 {
			start = i + 1
			break
		}

	}
	key := rule[start : pos-ti]

	end := pos + 2
	for i := pos + 2; i < len(rule)-1; i++ {
		if rule[i] != 92 && rule[i+1] == 34 {
			end = i + 2
			break
		}
	}
	value := rule[pos+2 : end-1]
	all := rule[start:end]

	return structs.RuleData{Start: start, End: end, Op: int16(op), Key: key, Value: value, All: all}
}

func ParseRule(rule string) []structs.RuleData {
	var result []structs.RuleData
	empty := structs.RuleData{}

	for {
		data := getRuleData(rule)
		if data == empty {
			break
		}
		result = append(result, data)
		rule = rule[:data.Start] + "T" + rule[data.End:]
	}
	return result
}

func regexMatch(pattern string, s string) (bool, error) {
	matched, err := regexp.MatchString(pattern, s)
	if err != nil {
		return false, err
	}
	return matched, nil
}

// body="123"  op=0  dataSource为http.body dataRule=123
func dataCheckString(op int16, dataSource string, dataRule string) bool {
	dataSource = strings.ToLower(dataSource)

	dataRule = strings.ToLower(dataRule)
	dataRule = strings.ReplaceAll(dataRule, "\\\"", "\"")
	if op == 0 {
		if strings.Contains(dataSource, dataRule) {
			return true
		}
	} else if op == 1 {
		if !strings.Contains(dataSource, dataRule) {
			return true
		}
	} else if op == 2 {
		if dataSource == dataRule {
			return true
		}
	} else if op == 5 {
		rs, err := regexMatch(dataRule, dataSource)
		if err == nil && rs {
			return true
		}
	}
	return false
}

func dataCheckInt(op int16, dataSource int, dataRule int) bool {
	if op == 0 { // 数字相等
		if dataSource == dataRule {
			return true
		}
	} else if op == 1 { // 数字不相等
		if dataSource != dataRule {
			return true
		}
	} else if op == 3 { // 大于等于
		if dataSource >= dataRule {
			return true
		}
	} else if op == 4 {
		if dataSource <= dataRule {
			return true
		}
	}
	return false
}

func checkPath(Path string,
	webPath structs.UrlPathEntity,
	Port int, // 所开放的端口
	Protocol string, // 协议
	Banner string, // 响应
	Cert string, // TLS证书
) []string {
	var fingerPrintResults []string

	isWeb := Path != "no#web" && webPath.Hash != ""

	hashString := webPath.Hash
	body := ""
	bodyBytes, ok := structs.GlobalHttpBodyHMap.Get(hashString)
	if !ok {
		body = ""
	} else {
		body = string(bodyBytes)
	}

	headerString := ""
	headerBytes, ok := structs.GlobalHttpHeaderHMap.Get(webPath.HeaderHashString)
	if !ok {
		headerString = ""
	} else {
		headerString = string(headerBytes)
	}

	workers := runtime.NumCPU() * 2
	inputChan := make(chan structs.FingerPEntity, len(structs.FingerprintDB))
	defer close(inputChan)
	results := make(chan string, len(structs.FingerprintDB))
	defer close(results)

	var wg sync.WaitGroup

	//接收结果
	go func() {
		for found := range results {
			if found != "" {
				fingerPrintResults = append(fingerPrintResults, found)
			}
			wg.Done()
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for finger := range inputChan {
				rules := finger.Rule
				product := finger.ProductName
				expr := finger.AllString

				for _, singleRule := range rules {
					singleRuleResult := false
					if singleRule.Key == "header" {
						if isWeb && dataCheckString(singleRule.Op, headerString, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "body" {
						if isWeb && dataCheckString(singleRule.Op, body, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "server" {
						if isWeb && dataCheckString(singleRule.Op, webPath.Server, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "title" {
						if isWeb && dataCheckString(singleRule.Op, webPath.Title, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "cert" {
						if dataCheckString(singleRule.Op, Cert, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "port" {
						value, err := strconv.Atoi(singleRule.Value)
						if err == nil && dataCheckInt(singleRule.Op, Port, value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "protocol" {
						if singleRule.Op == 0 {
							if Protocol == singleRule.Value {
								singleRuleResult = true
							}
						} else if singleRule.Op == 1 {
							if Protocol != singleRule.Value {
								singleRuleResult = true
							}
						}
					} else if singleRule.Key == "path" {
						if isWeb && dataCheckString(singleRule.Op, Path, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "body_hash" {

						if isWeb && dataCheckString(singleRule.Op, webPath.Hash, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "icon_hash" {
						value, err := strconv.Atoi(singleRule.Value)
						hashIcon, errHash := strconv.Atoi(webPath.IconHash)
						if isWeb && err == nil && errHash == nil && dataCheckInt(singleRule.Op, hashIcon, value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "status" {
						value, err := strconv.Atoi(singleRule.Value)
						if isWeb && err == nil && dataCheckInt(singleRule.Op, webPath.StatusCode, value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "content_type" {
						if isWeb && dataCheckString(singleRule.Op, webPath.ContentType, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "banner" {
						if dataCheckString(singleRule.Op, Banner, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "type" {
						if singleRule.Value == "service" {
							singleRuleResult = true
						}
					}
					if singleRuleResult {
						expr = expr[:singleRule.Start] + "T" + expr[singleRule.End:]
					} else {
						expr = expr[:singleRule.Start] + "F" + expr[singleRule.End:]
					}
				}

				r := boolEval(expr)
				if r {
					results <- product
				} else {
					results <- ""
				}

			}

		}()
	}

	//添加扫描目标
	for _, input := range structs.FingerprintDB {
		wg.Add(1)
		inputChan <- input
	}
	wg.Wait()

	return utils.RemoveDuplicateElement(fingerPrintResults)
}

func FingerprintIdentification() {
	gologger.Info().Msg("指纹识别中")

	// 先识别非Web
	for hostPort, protocol := range structs.GlobalIPPortMap {
		if protocol == "http" || protocol == "https" || protocol == "" {
			continue
		}
		t := strings.Split(hostPort, ":")
		if len(t) != 2 {
			continue
		}
		// host := t[0]
		port, err := strconv.Atoi(t[1])
		if err != nil {
			continue
		}
		banner := ""
		bodyBytes, ok := structs.GlobalBannerHMap.Get(hostPort)
		if !ok {
			banner = ""
		} else {
			banner = string(bodyBytes)
		}
		results := checkPath("no#web", structs.UrlPathEntity{}, port, protocol, banner, "")
		if len(results) > 0 {
			Url := fmt.Sprintf("%s://%s", protocol, hostPort)
			structs.GlobalResultMap[Url] = results

			//msg := "[Finger] " + Url + " ["
			//for _, r := range results {
			//	msg += aurora.Cyan(r).String() + ","
			//}
			//msg = msg[:len(msg)-1] + "]"
			//gologger.Silent().Msg(msg)

			ddout.FormatOutput(ddout.OutputMessage{
				Type:          "Finger",
				IP:            "",
				IPs:           nil,
				Port:          "",
				Protocol:      "",
				Web:           ddout.WebInfo{},
				Finger:        results,
				Domain:        "",
				GoPoc:         ddout.GoPocsResultType{},
				URI:           Url,
				AdditionalMsg: "",
			})

		}

	}
	for rootURL, urlEntity := range structs.GlobalURLMap {
		banner := ""
		if urlEntity.IP != "" {
			hostPort := fmt.Sprintf("%s:%d", urlEntity.IP, urlEntity.Port)

			bodyBytes, ok := structs.GlobalBannerHMap.Get(hostPort)
			if !ok {
				banner = ""
			} else {
				banner = string(bodyBytes)
			}
		}

		URL, _ := url.Parse(rootURL)

		for path, pathEntity := range urlEntity.WebPaths {
			results := checkPath(path, pathEntity, urlEntity.Port, URL.Scheme, banner, urlEntity.Cert)
			fullURL := rootURL + path

			if len(results) > 0 {
				structs.GlobalResultMap[fullURL] = results
				//msg := "[Finger] " + fullURL + " "
				//msg += fmt.Sprintf("[%d] [", pathEntity.StatusCode)
				//for _, r := range results {
				//	msg += aurora.Cyan(r).String() + ","
				//}
				//msg = msg[:len(msg)-1] + "]"
				//if pathEntity.Title != "" {
				//	msg += fmt.Sprintf(" [%s]", pathEntity.Title)
				//}
				//gologger.Silent().Msg(msg)
				ddout.FormatOutput(ddout.OutputMessage{
					Type:     "Finger",
					IP:       "",
					IPs:      nil,
					Port:     "",
					Protocol: "",
					Web: ddout.WebInfo{
						Status: strconv.Itoa(pathEntity.StatusCode),
						Title:  pathEntity.Title,
					},
					Finger:        results,
					Domain:        "",
					GoPoc:         ddout.GoPocsResultType{},
					URI:           fullURL,
					AdditionalMsg: "",
				})
			} else {
				structs.GlobalResultMap[fullURL] = []string{}
			}
		}
	}
	gologger.AuditTimeLogger("指纹识别结束")
}

func SingleCheck(finger structs.FingerPEntity, Protocol string, headerString string, body string,
	Server string, Title string, Cert string, Port int, Path string, Hash string, IconHash string, StatusCode int,
	ContentType string, Banner string) bool {
	rules := finger.Rule
	expr := finger.AllString

	for _, singleRule := range rules {
		singleRuleResult := false
		if singleRule.Key == "header" {
			if dataCheckString(singleRule.Op, headerString, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "body" {
			if dataCheckString(singleRule.Op, body, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "server" {
			if dataCheckString(singleRule.Op, Server, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "title" {
			if dataCheckString(singleRule.Op, Title, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "cert" {
			if dataCheckString(singleRule.Op, Cert, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "port" {
			value, err := strconv.Atoi(singleRule.Value)
			if err == nil && dataCheckInt(singleRule.Op, Port, value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "protocol" {
			if singleRule.Op == 0 {
				if Protocol == singleRule.Value {
					singleRuleResult = true
				}
			} else if singleRule.Op == 1 {
				if Protocol != singleRule.Value {
					singleRuleResult = true
				}
			}
		} else if singleRule.Key == "path" {
			if dataCheckString(singleRule.Op, Path, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "body_hash" {

			if dataCheckString(singleRule.Op, Hash, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "icon_hash" {
			value, err := strconv.Atoi(singleRule.Value)
			hashIcon, errHash := strconv.Atoi(IconHash)
			if err == nil && errHash == nil && dataCheckInt(singleRule.Op, hashIcon, value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "status" {
			value, err := strconv.Atoi(singleRule.Value)
			if err == nil && dataCheckInt(singleRule.Op, StatusCode, value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "content_type" {
			if dataCheckString(singleRule.Op, ContentType, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "banner" {
			if dataCheckString(singleRule.Op, Banner, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "type" {
			if singleRule.Value == "service" {
				singleRuleResult = true
			}
		}
		if singleRuleResult {
			expr = expr[:singleRule.Start] + "T" + expr[singleRule.End:]
		} else {
			expr = expr[:singleRule.Start] + "F" + expr[singleRule.End:]
		}
	}

	return boolEval(expr)
}
