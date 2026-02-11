//go:build !dev

package constants

// Production: only allow seawise.io domains for FRP connections.
var allowedFRPDomains = []string{
	".seawise.io",
}
