package app

import (
	"os"
	"time"

	"github.com/sondt/edge-guardian/internal/health"
	"github.com/sondt/edge-guardian/internal/web"
)

// maybeSeedHealthDemo populates the health branch with synthetic per-site traffic when
// EG_DEMO_SEED=1, so the /sites page and the Overview readout render with realistic
// data on first open. DEMO/DEV ONLY; never runs in production (env-gated). Returns true
// if it seeded.
func maybeSeedHealthDemo(h *health.Health) bool {
	if h == nil || os.Getenv("EG_DEMO_SEED") != "1" {
		return false
	}
	now := time.Now()
	// Spread traffic over the last ~30 minutes so per-minute sparklines have shape.
	type plan struct {
		host    string
		reqs    int     // per minute
		err5xx  float64 // fraction of requests that are 5xx
		latency float64 // typical request_time seconds
	}
	plans := []plan{
		{"baophapluat.vn", 240, 0.003, 0.18}, // healthy, busy
		{"daidoanket.vn", 38, 0.124, 1.8},    // degraded: high 5xx + slow
		{"tienphong.vn", 90, 0.01, 0.4},      // healthy
	}
	for m := 30; m >= 0; m-- {
		at := now.Add(-time.Duration(m) * time.Minute)
		for _, p := range plans {
			for i := 0; i < p.reqs; i++ {
				status := 200
				if float64(i)/float64(p.reqs) < p.err5xx {
					status = 503
				}
				upstreamErr := status == 503
				h.Observe(p.host, status, p.latency, 800, upstreamErr, at)
			}
		}
	}
	return true
}

// maybeSeedDemo populates the dashboard event store with synthetic, varied events when
// the EG_DEMO_SEED=1 environment variable is set (the local demo sets it).
//
// DEMO/DEV ONLY. These events are FABRICATED for the detector types not yet
// implemented (portscan, honeypot) so the dashboard's "by type" readout, Sentinel
// line and feed look complete. http, exploit and sshd are REAL detections from the
// demo's log files — not seeded here. This never runs in production (env-gated) and does
// not touch the ban ledger (which reflects only real detections).
func maybeSeedDemo(store *web.Store, now time.Time) {
	if store == nil || os.Getenv("EG_DEMO_SEED") != "1" {
		return
	}

	// Only the types that need kernel netfilter logs are synthetic; http, exploit and
	// sshd are REAL detections from the demo's access/auth logs (dev/attack.sh feeds them).
	detectors := []string{"portscan", "honeypot"}
	origins := []struct{ ip, country, asn string }{
		{"185.220.101.5", "DE", "AS24940 Hetzner"},
		{"45.13.22.7", "RU", "AS49505 Selectel"},
		{"92.118.39.10", "NL", "AS202425 IPV"},
		{"193.32.162.3", "RU", "AS56630 Melbikomas"},
		{"80.94.95.112", "BG", "AS200019 AlViNet"},
		{"141.98.10.61", "LT", "AS209605 UAB Cherry"},
		{"103.74.19.88", "VN", "AS135905 VNPT"},
		{"159.65.220.4", "US", "AS14061 DigitalOcean"},
		{"196.251.88.12", "ZA", "AS328543 Xneelo"},
		{"23.94.5.140", "US", "AS36352 ColoCrossing"},
		{"5.188.206.18", "RU", "AS49505 Selectel"},
		{"89.248.165.74", "NL", "AS202425 IPV"},
	}

	// Spread `total` events over the last `window`, biased toward "now" (quadratic) so
	// recent buckets are denser — the headline flips to "Under scan" and the recent
	// feed is full, while older buckets give the Sentinel line a textured trace.
	const total = 80
	window := 3 * time.Hour

	for i := range total {
		frac := float64(i) / float64(total) // 0 (oldest) → ~1 (newest)
		ago := time.Duration((1 - frac*frac) * float64(window))
		at := now.Add(-ago)

		d := detectors[i%len(detectors)] // even across the four types
		o := origins[(i*7)%len(origins)] // stride 7 (coprime to 12) = even spread
		action := "banned"
		if i%3 == 0 { // mix solid (banned) and hollow (would-ban) ticks
			action = "would-ban"
		}
		store.Push(web.Event{
			At:       at,
			IP:       o.ip,
			Detector: d,
			Action:   action,
			Country:  o.country,
			ASN:      o.asn,
		})
	}

	seedErrorsDemo(store, now)
}

// seedErrorsDemo fabricates a spread of 4xx/5xx requests across several hosts so the
// /errors page (filter + pagination) has realistic data in the demo. DEMO/DEV ONLY.
func seedErrorsDemo(store *web.Store, now time.Time) {
	hosts := []string{"baophapluat.vn", "daidoanket.vn", "tienphong.vn"}
	paths := []struct {
		path   string
		status int
	}{
		{"/wp-login.php", 403},
		{"/.env", 404},
		{"/xmlrpc.php?rsd", 403},
		{"/api/v1/orders", 502},
		{"/cgi-bin/login.cgi", 404},
		{"/admin/config.php", 500},
		{"/.git/config", 404},
		{"/wp-admin/admin-ajax.php", 503},
		{"/index.php?page=../../etc/passwd", 400},
		{"/search?q=%27", 500},
	}
	ips := []string{"45.13.22.7", "92.118.39.10", "185.220.101.5", "103.74.19.88", "159.65.220.4", "80.94.95.112"}

	// ~140 entries over the last 2 hours → enough to exercise pagination (>50/page).
	const total = 140
	window := 2 * time.Hour
	for i := range total {
		frac := float64(i) / float64(total)
		at := now.Add(-time.Duration((1-frac)*float64(window)) - time.Minute)
		p := paths[(i*3)%len(paths)]
		store.PushError(web.ErrorReq{
			At:     at,
			Host:   hosts[i%len(hosts)],
			IP:     ips[(i*5)%len(ips)],
			Path:   p.path,
			Status: p.status,
		})
	}
}
