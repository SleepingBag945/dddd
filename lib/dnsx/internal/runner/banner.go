package runner

import (
	updateutils "github.com/projectdiscovery/utils/update"
)

// Name
const ToolName = `dnsx`

// version is the current version of dnsx
const version = `1.1.4`

// GetUpdateCallback returns a callback function that updates dnsx
func GetUpdateCallback() func() {
	return func() {
		updateutils.GetUpdateToolCallback("dnsx", version)()
	}
}
