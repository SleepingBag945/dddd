package httpx

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	errorutil "github.com/projectdiscovery/utils/errors"
	"os"
	"strings"
)

func RemoveDuplicateElement(input []string) []string {
	temp := map[string]struct{}{}
	var result []string
	for _, item := range input {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func RemoveUsedUrl(urls []string) []string {
	var result []string
	for _, u := range urls {
		flag := false
		for _, gu := range GlobalUsedUrl {
			if gu == u {
				flag = true
				break
			}
		}
		if !flag {
			result = append(result, u)
		}
	}
	return RemoveDuplicateElement(result)
}

var GlobalUsedUrl []string

func CallHTTPx(urls []string, callBack func(resp runner.Result), proxy string, threads int, timeout int) {
	gologger.Info().Msg("获取Web响应中")

	nextUrls := RemoveDuplicateElement(urls)
	gologger.AuditLogger("响应探测目标: %s", strings.Join(nextUrls, ","))

	times := 0
	for len(nextUrls) > 0 && times < 3 {
		options := runner.Options{
			Methods:                   "GET",
			InputTargetHost:           nextUrls,
			Favicon:                   true,
			Hashes:                    "md5",
			OutputServerHeader:        true,
			TLSProbe:                  true,
			MaxResponseBodySizeToRead: 1048576,
			FollowHostRedirects:       true,
			MaxRedirects:              5,
			ExtractTitle:              true,
			Timeout:                   timeout,
			Retries:                   2,
			HTTPProxy:                 proxy,
			NoFallbackScheme:          true,
			RandomAgent:               true,
			Threads:                   threads,
		}

		if err := options.ValidateOptions(); err != nil {
			gologger.Error().Msgf("params error")
		}

		httpxRunner, err := runner.New(&options)
		if err != nil {
			gologger.Error().Msgf("runner.New(&options) error")
		}
		httpxRunner.CallBack = callBack

		for _, u := range nextUrls {
			GlobalUsedUrl = append(GlobalUsedUrl, u)
		}
		GlobalUsedUrl = RemoveDuplicateElement(GlobalUsedUrl)

		httpxRunner.RunEnumeration()
		nextUrls = RemoveUsedUrl(httpxRunner.NextCheckUrl)
		httpxRunner.Close()
		times += 1

	}
	gologger.AuditTimeLogger("响应探测结束")

}

func init() {
	if os.Getenv("DEBUG") != "" {
		errorutil.ShowStackTrace = true
	}
}

func DirBrute(urls []string, callBack func(resp runner.Result), proxy string, threads int, timeout int) {
	urls = RemoveDuplicateElement(urls)

	options := runner.Options{
		Methods:                   "GET",
		InputTargetHost:           urls,
		Hashes:                    "md5",
		OutputServerHeader:        true,
		TLSProbe:                  true,
		MaxResponseBodySizeToRead: 1048576,
		FollowHostRedirects:       true,
		MaxRedirects:              5,
		ExtractTitle:              true,
		Timeout:                   timeout,
		IsBrute:                   true,
		Retries:                   2,
		HTTPProxy:                 proxy,
		NoFallbackScheme:          true,
		RandomAgent:               true,
		Threads:                   threads,
	}

	if err := options.ValidateOptions(); err != nil {
		gologger.Error().Msgf("params error")
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		gologger.Error().Msgf("runner.New(&options) error")
	}
	httpxRunner.CallBack = callBack

	httpxRunner.RunEnumeration()
	httpxRunner.Close()
}
