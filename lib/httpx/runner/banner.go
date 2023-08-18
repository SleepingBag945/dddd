package runner

import (
	updateutils "github.com/projectdiscovery/utils/update"
)

// Version is the current version of httpx
const version = `v1.3.1`

// showBanner is used to show the banner to the user
func showBanner() {
}

// GetUpdateCallback returns a callback function that updates httpx
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("httpx", version)()
	}
}
