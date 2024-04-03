package calldnsx

import (
	"github.com/projectdiscovery/dnsx/internal/runner"
	"github.com/projectdiscovery/gologger"
)

func CallDNSx(domain string, threads int, callback func(subdomain string), defaultDict []string, dictPath string) []string {
	// Parse the command line flags and read config files
	options := runner.ParseOptions(domain, dictPath, threads)

	dnsxRunner, err := runner.New(options)
	dnsxRunner.DNSxCallback = callback
	dnsxRunner.DefaultDict = defaultDict
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	gologger.Info().Msgf("暴力破解子域名: %v", domain)
	// nolint:errcheck
	dnsxRunner.Run()
	dnsxRunner.Close()
	return dnsxRunner.GetResults()
}
