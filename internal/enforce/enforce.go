// Package enforce enforces bans at the kernel level using an nftables named set with timeout.
//
// nftables operations are Linux-only (native netlink). The real implementation lives in
// nft_linux.go (build tag linux); nft_other.go provides a stub so the whole module still
// builds/tests on other OSes (macOS dev). The interface and config live here so they are
// platform-independent.
package enforce

import (
	"log/slog"
	"net/netip"
	"time"
)

// Config holds nftables parameters, taken from the [ban] block of the config file.
type Config struct {
	Table      string
	SetV4      string
	SetV6      string
	BlockSetV4 string // interval set for imported public blocklists (CIDR)
	BlockSetV6 string
}

// Enforcer adds/removes IPs from the nftables blocklist.
type Enforcer interface {
	// Ban adds ip to the corresponding set (v4/v6) with the remaining timeout.
	Ban(ip netip.Addr, timeout time.Duration) error
	// Unban removes ip from the set. A non-existent entry is not an error.
	Unban(ip netip.Addr) error
	// ReplaceBlockset replaces the entire contents of the imported blocklist interval
	// set with the given prefixes (flush + reload). Used for periodic public blocklist imports.
	ReplaceBlockset(v4, v6 []netip.Prefix) error
	// EnsureBaselineAccept guarantees the input chain accepts loopback and established/
	// related connections BEFORE any drop rule, repairing the chain if those rules are
	// absent. Without them, a blocked range overlapping loopback/LAN — or the host's own
	// return traffic — is blackholed (the 504 outage). Idempotent and best-effort: it only
	// inserts missing rules and never fails daemon start. The stub (non-Linux) is a no-op.
	EnsureBaselineAccept(log *slog.Logger)
	// Close releases the netlink connection.
	Close() error
}

// New returns an Enforcer suited to the platform (real nftables on Linux, stub elsewhere).
func New(cfg Config) (Enforcer, error) {
	return newPlatform(cfg)
}
