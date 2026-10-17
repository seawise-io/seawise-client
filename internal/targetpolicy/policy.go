package targetpolicy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/seawise/client/internal/store"
)

// Grants beyond private addresses, confirmed locally per app.
const (
	GrantPublic    = "public"
	GrantLoopback  = "loopback"
	GrantSensitive = "sensitive"
	GrantSMTP      = "smtp"
	GrantGateway   = "gateway"
)

var allGrants = []string{GrantGateway, GrantLoopback, GrantPublic, GrantSensitive, GrantSMTP}

// grandfatheredGrants keep existing apps working after an upgrade.
// Management API ports are not among them: those need an explicit review.
var grandfatheredGrants = []string{GrantGateway, GrantLoopback, GrantPublic, GrantSMTP}

// SensitivePorts are management APIs that must not be shared by accident.
var SensitivePorts = map[int]string{
	2375: "Docker API", 2376: "Docker API", 2377: "Docker swarm",
	2379: "etcd", 2380: "etcd", 6443: "Kubernetes API", 10250: "kubelet", 10255: "kubelet",
}

// SMTPPorts on a public address need their own confirmation.
var SMTPPorts = map[int]bool{25: true, 465: true, 587: true}

var ErrRefused = errors.New("target refused")

// Rule is what the policy needs to know about one app.
type Rule struct {
	Host          string
	Grants        []string
	Grandfathered bool
}

// RuleFor builds the rule for a stored target. A grandfathered target that
// has not been reviewed keeps the grants it needs to work as before, except
// for management API ports.
func RuleFor(t store.Target) Rule {
	return Rule{Host: t.Host, Grants: t.Allowed, Grandfathered: t.Grandfathered}
}

func (r Rule) has(g string) bool {
	return slices.Contains(r.Grants, g) || (r.Grandfathered && slices.Contains(grandfatheredGrants, g))
}

// IntendedLoopback reports whether host itself names this machine.
func IntendedLoopback(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.Unmap().IsLoopback()
}

// Requirement is the outcome of evaluating one address.
type Requirement struct {
	Class    Class
	Required []string
	Refused  string
	Reasons  []string
}

// Evaluate returns what reaching ap needs for an app whose host is host.
func Evaluate(host string, ap netip.AddrPort, gateways []netip.Addr) Requirement {
	addr := ap.Addr().WithZone("").Unmap()
	c, reason := Classify(addr)
	req := Requirement{Class: c}
	port := int(ap.Port())
	switch c {
	case Forbidden:
		req.Refused = reason
		return req
	case Loopback:
		if !IntendedLoopback(host) {
			req.Refused = "name resolves to this machine's loopback address"
			return req
		}
		req.Required = append(req.Required, GrantLoopback)
		req.Reasons = append(req.Reasons, "this machine")
	case Public:
		req.Required = append(req.Required, GrantPublic)
		req.Reasons = append(req.Reasons, "public address")
		if SMTPPorts[port] {
			req.Required = append(req.Required, GrantSMTP)
			req.Reasons = append(req.Reasons, "mail port")
		}
	}
	// Management API ports need their own grant on every class.
	if name, ok := SensitivePorts[port]; ok {
		req.Required = append(req.Required, GrantSensitive)
		req.Reasons = append(req.Reasons, name)
	} else if c != Public && slices.Contains(gateways, addr) {
		req.Required = append(req.Required, GrantGateway)
		req.Reasons = append(req.Reasons, "network gateway")
	}
	return req
}

// Check decides one connection. It is called with the resolved address.
func Check(r Rule, ap netip.AddrPort, gateways []netip.Addr) error {
	req := Evaluate(r.Host, ap, gateways)
	if req.Refused != "" {
		return fmt.Errorf("%w: %s: %s", ErrRefused, ap.Addr(), req.Refused)
	}
	for _, g := range req.Required {
		if !r.has(g) {
			return fmt.Errorf("%w: %s needs local confirmation (%s)", ErrRefused, ap.Addr(), g)
		}
	}
	return nil
}

// Dialer returns a copy of base whose Control hook runs Check on every
// connection attempt, after name resolution.
func Dialer(base *net.Dialer, r Rule, gateways []netip.Addr) *net.Dialer {
	d := &net.Dialer{}
	if base != nil {
		*d = *base
	}
	prev := d.Control
	d.ControlContext = nil
	d.Control = func(network, address string, c syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("%w: unparseable address %q", ErrRefused, address)
		}
		if err := Check(r, ap, gateways); err != nil {
			return err
		}
		if prev != nil {
			return prev(network, address, c)
		}
		return nil
	}
	return d
}

type Options struct {
	// PublicAllowed is the operator opt-in for public targets on new apps.
	PublicAllowed bool
}

// Assessment is what a new or reviewed app needs before it may be used.
type Assessment struct {
	Classes  []Class  `json:"classes"`
	Required []string `json:"required"`
	Reasons  []string `json:"reasons,omitempty"`
	Refused  string   `json:"refused,omitempty"`
}

// Assess evaluates every resolved address of host:port. Any refused address
// refuses the app; the required grants are the union.
func Assess(host string, port int, resolved []netip.Addr, gateways []netip.Addr, opts Options) Assessment {
	out := Assessment{Classes: []Class{}, Required: []string{}}
	if len(resolved) == 0 {
		out.Refused = "host did not resolve"
		return out
	}
	if port < 1 || port > 65535 {
		out.Refused = "port out of range"
		return out
	}
	classes, required, reasons := map[Class]bool{}, map[string]bool{}, map[string]bool{}
	for _, a := range resolved {
		req := Evaluate(host, netip.AddrPortFrom(a, uint16(port)), gateways)
		classes[req.Class] = true
		if req.Refused != "" && out.Refused == "" {
			out.Refused = req.Refused
		}
		for _, g := range req.Required {
			required[g] = true
		}
		for _, r := range req.Reasons {
			reasons[r] = true
		}
	}
	if out.Refused == "" && required[GrantPublic] && !opts.PublicAllowed {
		out.Refused = "public targets are turned off on this client"
	}
	for c := range classes {
		out.Classes = append(out.Classes, c)
	}
	sort.Slice(out.Classes, func(i, j int) bool { return out.Classes[i] < out.Classes[j] })
	for _, g := range allGrants {
		if required[g] {
			out.Required = append(out.Required, g)
		}
	}
	for r := range reasons {
		out.Reasons = append(out.Reasons, r)
	}
	sort.Strings(out.Reasons)
	return out
}
