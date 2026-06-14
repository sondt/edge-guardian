// Package allow implements a CIDR allowlist — a line of defense against locking yourself out.
package allow

import (
	"net/netip"
)

// List is an immutable list of prefixes; checks whether an IP is exempt from banning.
type List struct {
	prefixes []netip.Prefix
}

// New creates an allowlist from the parsed prefixes.
func New(prefixes []netip.Prefix) *List {
	cp := make([]netip.Prefix, len(prefixes))
	copy(cp, prefixes)
	return &List{prefixes: cp}
}

// Contains returns true if addr falls within any prefix.
// An invalid addr is treated as NOT in the allowlist (the caller handles it).
func (l *List) Contains(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, p := range l.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ContainsString is a convenience: parse the IP string then check it.
// Returns (false, false) if the string is not a valid IP.
func (l *List) ContainsString(ip string) (allowed bool, valid bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, false
	}
	return l.Contains(addr), true
}
