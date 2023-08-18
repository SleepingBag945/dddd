package common

import (
	"bytes"
	"dddd/structs"
	"dddd/utils"
	"github.com/projectdiscovery/dnsx/calldnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"io"
	"log"
	"strings"
)

func SubFinder(domain string) []string {
	runnerInstance, err := runner.NewRunner(&runner.Options{
		Threads:            10,                       // Thread controls the number of threads to use for active enumerations
		Timeout:            30,                       // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10,                       // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Resolvers:          resolve.DefaultResolvers, // Use the default list of resolvers by marshaling it to the config
		ResultCallback: func(s *resolve.HostEntry) { // Callback function to execute for available host
			gologger.Silent().Msgf("[%s] %s", s.Source, s.Host)
		},
		RemoveWildcard:     true,
		DisableUpdateCheck: true,
	})
	err = runner.UnmarshalFrom("config/subfinder-config.yaml")
	if err != nil {
		log.Fatal(err)
	}

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

func GetSubDomain(domains []string) []string {
	var results []string
	for _, domain := range domains {

		// 爆破子域名
		if !structs.GlobalConfig.NoSubdomainBruteForce {
			br := calldnsx.CallDNSx(domain, structs.GlobalConfig.SubdomainBruteForceThreads)
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
