//go:build dev

package constants

// Development: include localhost and Docker entries for local testing.
var allowedFRPDomains = []string{
	".seawise.dev",
	".seawise.io",
	"localhost",
	"host.docker.internal",
}
