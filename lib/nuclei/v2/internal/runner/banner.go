package runner

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	updateutils "github.com/projectdiscovery/utils/update"
)

// NucleiToolUpdateCallback updates nuclei binary/tool to latest version
func NucleiToolUpdateCallback() {
	updateutils.GetUpdateToolCallback("nuclei", config.Version)()
}
