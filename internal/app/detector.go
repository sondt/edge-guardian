package app

import "github.com/sondt/edge-guardian/internal/detect"

// Detector is a detection source: it inspects each log line, and on a "hit" returns the IP,
// an optional sub-key (sub), and a reason; then counts via its own Counter before deciding
// to ban.
//
//   - empty sub + Counter is Hits → counts the number of events (HTTP/SSH/honeypot).
//   - sub = port + Counter is Distinct → counts the number of DISTINCT ports (port scan).
//
// Detectors use disjoint patterns, so each line matches only one detector — the daemon runs
// every detector on every line, with no need to route by file. Adding a new source = add one
// Detector, no pipeline changes.
type Detector struct {
	Name    string
	Inspect func(line string) (ip, sub, reason string, ok bool)
	Window  detect.Counter
}
