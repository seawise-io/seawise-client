//go:build dev

package controlplane

// Development builds may reach a local API through Docker's host alias.
const allowDockerHostHTTP = true
