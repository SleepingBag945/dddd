// Package runner executes the enumeration process.
package runner

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	updateutils "github.com/projectdiscovery/utils/update"
)

// NucleiToolUpdateCallback updates nuclei binary/tool to latest version
func NucleiToolUpdateCallback() {
	updateutils.GetUpdateToolCallback(config.BinaryName, config.Version)()
}

// AuthWithPDCP is used to authenticate with PDCP
func AuthWithPDCP() {
	pdcpauth.CheckNValidateCredentials(config.BinaryName)
}
