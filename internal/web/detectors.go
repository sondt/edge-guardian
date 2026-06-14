package web

import "github.com/a-h/templ"

// detectorInfo describes one detector for the read-only Detectors screen.
type detectorInfo struct {
	Key     string // matches Event.Detector
	Desc    string
	Watches string
}

// knownDetectors is the fixed catalogue the daemon ships. Kept here (UI-owned) so the
// Detectors screen renders without a richer DataSource; activity shares come from the
// live Metrics. Descriptions are plain, active-voice, no feature-selling.
func knownDetectors() []detectorInfo {
	return []detectorInfo{
		{
			Key:     "http",
			Desc:    "Flags probes for known-vulnerable paths and login endpoints in the web access log.",
			Watches: "HTTP access log",
		},
		{
			Key:     "exploit",
			Desc:    "Matches attack signatures (SQLi, path traversal, RCE probes, Log4Shell) in request URIs. Off by default.",
			Watches: "HTTP access log",
		},
		{
			Key:     "badbot",
			Desc:    "Bans known scanner and pentest-tool user-agents (sqlmap, nikto, nuclei, masscan…). Off by default.",
			Watches: "HTTP access log",
		},
		{
			Key:     "portscan",
			Desc:    "Catches a single source touching many ports in a short window.",
			Watches: "Connection tracking",
		},
		{
			Key:     "honeypot",
			Desc:    "Treats any connection to an unused decoy port as hostile.",
			Watches: "Decoy ports",
		},
		{
			Key:     "sshd",
			Desc:    "Bans repeated failed SSH authentication from the same source.",
			Watches: "sshd auth log",
		},
		{
			Key:     "ratelimit",
			Desc:    "Bans a single IP that floods past a request-rate threshold (DoS-lite). Off by default; allowlist your proxies.",
			Watches: "HTTP access log",
		},
	}
}

// detectorShare returns the recent activity fraction (0..1) for a detector key.
func detectorShare(m Metrics, key string) float64 {
	for _, d := range m.Detectors {
		if d.Name == key {
			return d.Share
		}
	}
	return 0
}

// unbanURL builds the POST target for an unban action as a templ.SafeURL. The IP is
// path-escaped so IPv6 / unusual values can't break the URL.
func unbanURL(ip string) templ.SafeURL {
	return templ.URL("/bans/" + pathEscape(ip) + "/unban")
}
