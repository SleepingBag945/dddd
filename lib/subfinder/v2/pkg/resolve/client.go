package resolve

import (
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// DefaultResolvers contains the default list of resolvers known to be good
var DefaultResolvers = []string{
	"223.5.5.5:53",       // Cloudflare primary
	"223.6.6.6:53",       // Cloudflare secondary
	"114.114.114.114:53", // Google primary
	"114.114.115.115:53", // Google secondary
	"180.76.76.76:53",    // Quad9 Primary
	"119.29.29.29:53",    // Quad9 Secondary
	"182.254.116.116:53", // Yandex Primary
}

// Resolver is a struct for resolving DNS names
type Resolver struct {
	DNSClient *dnsx.DNSX
	Resolvers []string
}

// New creates a new resolver struct with the default resolvers
func New() *Resolver {
	return &Resolver{
		Resolvers: []string{},
	}
}
