package web

import (
	"context"
	"net"
	"strings"
	"time"
)

// Config maps the [dashboard] config block from the daemon's configuration file.
type Config struct {
	Enabled      bool
	Listen       string // default "127.0.0.1:8787" — NEVER default to 0.0.0.0
	Username     string
	PasswordHash string // bcrypt hash of the dashboard password
	// HealthWindowMins is the health snapshot window, shown on the /sites page. 0 hides
	// the "Sites" nav link (health disabled).
	HealthWindowMins int
}

// DefaultListen is the safe bind address: loopback only. The daemon (or withDefaults)
// must never substitute 0.0.0.0 — remote access goes through SSH tunnel or a TLS
// reverse proxy.
const DefaultListen = "127.0.0.1:8787"

// withDefaults returns a copy of cfg with empty fields filled by safe defaults. It
// never widens the bind address beyond loopback.
func (c Config) withDefaults() Config {
	out := c
	if out.Listen == "" {
		out.Listen = DefaultListen
	}
	return out
}

// Event is pushed by the detection pipeline into the ring buffer on every detection.
type Event struct {
	At       time.Time
	IP       string
	Detector string // "http" | "exploit" | "badbot" | "ratelimit" | "portscan" | "honeypot" | "sshd"
	Action   string // "banned" | "would-ban"
	Country  string // may be empty
	ASN      string // may be empty
}

// Ban is one row of the ledger: the read model the daemon supplies for currently
// active bans.
type Ban struct {
	IP        string
	Detector  string
	Reason    string // what triggered the ban, e.g. the matched scanner path "/wp-login.php"
	FirstSeen time.Time
	ExpiresAt time.Time
	Country   string
	ASN       string
	Location  string // human-readable "City, Region, Country" from GeoIP; may be empty
	Hits      int
}

// isLoopbackListen reports whether a listen address binds only loopback. Used to
// decide whether session cookies should be marked Secure (they must not be on a plain
// HTTP loopback bind, or the browser drops them).
func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	host = strings.TrimSpace(host)
	if host == "" || strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// SiteHealth is the read model for one monitored site on the /sites page and the
// Overview "Site health" readout. The daemon supplies it from the health branch; empty
// slice means health is disabled or no traffic seen yet.
type SiteHealth struct {
	Host        string
	Status      string // "Healthy" | "Degraded" | "Down" | "Idle"
	Reqs        uint64
	ReqPerSec   float64
	Err5xxPct   float64 // 0..100
	HasLatency  bool
	P95Sec      float64
	UpstreamErr uint64
	Spark       []int // per-minute request counts, oldest→newest
}

// DataSource is what the dashboard consumes from the running daemon. The daemon
// implements this over its live ban state.
type DataSource interface {
	// Bans returns the currently active bans. The dashboard does not mutate the
	// returned slice.
	Bans() []Ban
	// Unban removes the ban for ip. It must be safe to call concurrently and should
	// return a non-nil error if the IP is unknown or removal fails.
	Unban(ctx context.Context, ip string) error
	// SiteHealth returns per-site health for the /sites page. Empty when health is off.
	SiteHealth() []SiteHealth
}
