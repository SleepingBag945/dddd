package api

import (
	"dddd/common/callnuclei"
	"dddd/config"
	"dddd/structs"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"strings"
)

func PocCheck(target string,appName string)  {
	//pocList := searchPoc(target,appName)
	//gologger.Info().Label("加载").Msg(strings.Join(pocList[target],","))
	//structs.GlobalConfig.HTTPProxy = "http://127.0.0.1:8080"
	//if len(pocList) >0{
	//	callnuclei.CallNuclei(pocList, structs.GlobalConfig.HTTPProxy, callback)
	//}
	pocList := make(map[string][]string)
	pocs := config.SelectPoc(appName)
	pocList[target] = pocs
	gologger.Info().Label("加载").Msg(strings.Join(pocList[target],","))
	//structs.GlobalConfig.HTTPProxy = "http://127.0.0.1:8080"
	if len(pocList) >0{
		callnuclei.CallNuclei(pocList, structs.GlobalConfig.HTTPProxy, callback)
	}

}

func callback(result output.ResultEvent){
	gologger.Info().Label("SUCESS").Msg(result.Info.Name)
}

//func searchPoc(target string,appName string)(map[string][]string){
//	result := make(map[string][]string)
//	common.ReadWorkFlowDB()
//	for k, workflowEntity := range structs.WorkFlowDB {
//		if strings.Contains(strings.ToLower(k), strings.ToLower(appName)) {
//				result[target] = workflowEntity.PocsName
//			}
//		}
//	return result
//}

func test()  {
	PocCheck("https://www.baidu.com","seeyon")
}
