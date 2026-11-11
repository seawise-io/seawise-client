//go:build dev

package transport

import "strings"

// Development builds also dial pool names under .localhost, which resolve
// only on the local machine or a local container network.
func poolDomainAllowed(domain string) bool {
	return domain == poolDomain || (strings.HasSuffix(domain, ".localhost") && !strings.HasPrefix(domain, "."))
}
