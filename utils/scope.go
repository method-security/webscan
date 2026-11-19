package utils

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Scope is the seed domains and CIDRs a scan may follow and report beyond its target.
type Scope struct {
	Domains []string
	Cidrs   []string
}

// NewScope normalizes seed domains and CIDRs, returning nil when both are empty.
func NewScope(domains []string, cidrs []string) (*Scope, error) {
	scope := &Scope{Domains: []string{}, Cidrs: []string{}}
	for _, raw := range domains {
		value := strings.TrimSpace(raw)
		if strings.Contains(value, "://") {
			parsed, err := url.Parse(value)
			if err != nil {
				return nil, fmt.Errorf("invalid scope domain %q: %w", raw, err)
			}
			value = parsed.Hostname()
		}
		value = strings.TrimPrefix(normalizeHost(value), "*.")
		if value == "" || value == unrestrictedDomain {
			return nil, fmt.Errorf("invalid scope domain %q", raw)
		}
		if addr, err := netip.ParseAddr(value); err == nil {
			scope.Cidrs = append(scope.Cidrs, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()).String())
			continue
		}
		scope.Domains = append(scope.Domains, value)
	}
	for _, raw := range cidrs {
		prefix, err := parsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid scope CIDR %q: %w", raw, err)
		}
		scope.Cidrs = append(scope.Cidrs, prefix.String())
	}
	if len(scope.Domains) == 0 && len(scope.Cidrs) == 0 {
		return nil, nil
	}
	return scope, nil
}

// ScopeOf returns the seed scope for a config's flat scope fields, or nil when both are empty.
func ScopeOf(domains []string, cidrs []string) *Scope {
	if len(domains) == 0 && len(cidrs) == 0 {
		return nil
	}
	return &Scope{Domains: domains, Cidrs: cidrs}
}

// HostInSeedScope reports whether candidateURL's host is under a scope domain or inside a scope CIDR.
func HostInSeedScope(scope *Scope, candidateURL string) bool {
	if scope == nil {
		return false
	}
	parsed, err := url.Parse(candidateURL)
	if err != nil {
		return false
	}
	host := normalizeHost(parsed.Hostname())
	if host == "" {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		for _, cidr := range scope.Cidrs {
			if prefix, err := parsePrefix(cidr); err == nil && prefix.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, domain := range scope.Domains {
		if domain == unrestrictedDomain || host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// HostAllowed reports whether candidateURL is the anchor's host, under it, or under a seed.
func HostAllowed(scope *Scope, anchorURL string, candidateURL string) bool {
	return IsHostInScope(anchorURL, candidateURL) || HostInSeedScope(scope, candidateURL)
}

// unrestrictedDomain admits every host; only checks that exist to inspect third-party references use it.
const unrestrictedDomain = "*"

// UnrestrictedScope admits every host.
func UnrestrictedScope() *Scope {
	return &Scope{Domains: UnrestrictedDomains(), Cidrs: UnrestrictedCidrs()}
}

// UnrestrictedDomains is the domain list of UnrestrictedScope, for flat scope fields.
func UnrestrictedDomains() []string {
	return []string{unrestrictedDomain}
}

// UnrestrictedCidrs is the CIDR list of UnrestrictedScope, for flat scope fields.
func UnrestrictedCidrs() []string {
	return []string{"0.0.0.0/0", "::/0"}
}

// ScopeWithAnchor returns scope widened to include the anchor's host and its subdomains.
func ScopeWithAnchor(scope *Scope, anchorURL string) *Scope {
	widened := &Scope{Domains: []string{}, Cidrs: []string{}}
	if scope != nil {
		widened.Domains = append(widened.Domains, scope.Domains...)
		widened.Cidrs = append(widened.Cidrs, scope.Cidrs...)
	}
	parsed, err := url.Parse(anchorURL)
	if err != nil {
		return widened
	}
	host := normalizeHost(parsed.Hostname())
	if host == "" {
		return widened
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		widened.Cidrs = append(widened.Cidrs, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()).String())
		return widened
	}
	widened.Domains = append(widened.Domains, host)
	return widened
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func parsePrefix(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
