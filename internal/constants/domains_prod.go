//go:build !dev

package constants

// Production: only allow seawise.dev domains for FRP connections.
var allowedFRPDomains = []string{
	".seawise.dev",
}
