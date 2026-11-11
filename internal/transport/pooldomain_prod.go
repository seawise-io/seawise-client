//go:build !dev

package transport

func poolDomainAllowed(domain string) bool { return domain == poolDomain }
