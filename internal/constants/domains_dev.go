//go:build dev

package constants

// Development: include localhost and Docker entries for local testing.
var allowedFRPDomains = []string{
	".seawise.dev",
	".seawise.io",
	"localhost",
	"127.0.0.1",
	"host.docker.internal",
}
