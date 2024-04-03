package common

import (
	"bytes"
	"dddd/ddout"
	"dddd/structs"
	"dddd/utils"
	_ "embed"
	"github.com/projectdiscovery/dnsx/calldnsx"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"io"
	"log"
	"strings"
)

func SubFinder(domain string) []string {
	runnerInstance, err := runner.NewRunner(&runner.Options{
		Threads:            10,                       // Thread controls the number of threads to use for active enumerations
		Timeout:            15,                       // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 5,                        // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Resolvers:          resolve.DefaultResolvers, // Use the default list of resolvers by marshaling it to the config
		ResultCallback: func(s *resolve.HostEntry) { // Callback function to execute for available host
			// gologger.Silent().Msgf("[%s] %s", s.Source, s.Host)
			ddout.FormatOutput(ddout.OutputMessage{
				Type:          "DNS-SubFinder",
				IP:            "",
				IPs:           nil,
				Port:          "",
				Protocol:      "",
				Web:           ddout.WebInfo{},
				Finger:        nil,
				Domain:        s.Host,
				AdditionalMsg: s.Source,
			})
		},
		RemoveWildcard:     true,
		DisableUpdateCheck: true,
		ProviderConfig:     structs.GlobalConfig.APIConfigFilePath,
	})

	buf := bytes.Buffer{}
	err = runnerInstance.EnumerateSingleDomain(domain, []io.Writer{&buf})
	if err != nil {
		log.Fatal(err)
	}

	data, err := io.ReadAll(&buf)
	if err != nil {
		log.Fatal(err)
	}

	return strings.Split(string(data), "\n")
}

func DNSCallback(subdomain string) {
	ddout.FormatOutput(ddout.OutputMessage{
		Type:   "DNS-Brute",
		Domain: subdomain,
	})
}

//go:embed config/subdomains.txt
var EmbedSubdomainDict string

func GetSubDomain(domains []string) []string {
	var results []string

	// 兼容Windows输入
	t := strings.ReplaceAll(EmbedSubdomainDict, "\r\n", "\n")
	dict := strings.Split(t, "\n")

	for _, domain := range domains {

		// 爆破子域名
		if !structs.GlobalConfig.NoSubdomainBruteForce {
			br := calldnsx.CallDNSx(domain,
				structs.GlobalConfig.SubdomainBruteForceThreads,
				DNSCallback, dict, structs.GlobalConfig.SubdomainWordListFile)
			for _, v := range br {
				results = append(results, v)
			}
		}

		// subfinder被动收集
		if !structs.GlobalConfig.NoSubFinder {
			r := SubFinder(domain)
			for _, v := range r {
				results = append(results, v)
			}
		}

	}

	return utils.RemoveDuplicateElement(results)
}
