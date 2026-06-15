package health

import (
	"sync"
	"time"
)

// maxSites caps the number of hosts tracked when no fixed `sites` list is declared —
// preventing the map from growing if the Host in the log is anomalous (even though $host is
// usually bounded by server_name). Once the cap is reached, new hosts are dropped instead of allocated unboundedly.
const maxSites = 256

// Health holds rolling per-site counters. Bounded by (number of sites × number of minutes), NOT by
// request volume. Safe for concurrent access.
type Health struct {
	windowMins int
	allow      map[string]struct{} // fixed site list; empty = accept any host
	th         Thresholds
	now        func() time.Time

	mu    sync.Mutex
	sites map[string]*SiteSeries
}

// Config initializes Health.
type Config struct {
	WindowMins int
	Sites      []string // empty = track every host seen in the log
	Thresholds Thresholds
	Now        func() time.Time // nil = time.Now
}

// New creates a Health from Config.
func New(c Config) *Health {
	if c.WindowMins < 1 {
		c.WindowMins = 180
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	var allow map[string]struct{}
	sites := make(map[string]*SiteSeries)
	if len(c.Sites) > 0 {
		allow = make(map[string]struct{}, len(c.Sites))
		for _, s := range c.Sites {
			allow[s] = struct{}{}
			// Pre-register each declared/discovered site so it shows on the dashboard
			// (as "Idle") even before any request — the count reflects every site nginx
			// serves, not only those that have seen traffic.
			sites[s] = newSeries(c.WindowMins)
		}
	}
	return &Health{
		windowMins: c.WindowMins,
		allow:      allow,
		th:         c.Thresholds,
		now:        now,
		sites:      sites,
	}
}

// minuteOf returns the Unix minute of t.
func minuteOf(t time.Time) int64 { return t.Unix() / 60 }

// Observe records one observation for host at time now. Empty host → folded into "all" (the
// combined log has no $host). Sites outside the `sites` list (if declared) are skipped.
func (h *Health) Observe(host string, status int, rtSec float64, bytes uint64, upstreamErr bool, now time.Time) {
	if host == "" {
		host = "all"
	}
	if h.allow != nil {
		if _, ok := h.allow[host]; !ok {
			return
		}
	}
	minute := minuteOf(now)

	h.mu.Lock()
	defer h.mu.Unlock()

	s := h.sites[host]
	if s == nil {
		if h.allow == nil && len(h.sites) >= maxSites {
			return // prevent the map from growing with anomalous hosts
		}
		s = newSeries(h.windowMins)
		h.sites[host] = s
	}
	s.observe(minute, status, rtSec, bytes, upstreamErr)
}

// Snapshot captures one site over a window of windowMins minutes (clamped to the config). Returns ok
// false if the site has never been seen.
func (h *Health) Snapshot(host string, windowMins int) (SiteStats, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sites[host]
	if s == nil {
		return SiteStats{}, false
	}
	return h.snapshotLocked(host, s, windowMins), true
}

// SnapshotAll captures every site, sorted by host.
func (h *Health) SnapshotAll(windowMins int) []SiteStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]SiteStats, 0, len(h.sites))
	for host, s := range h.sites {
		out = append(out, h.snapshotLocked(host, s, windowMins))
	}
	byHost(out)
	return out
}

// snapshotLocked aggregates one site (caller holds mu).
func (h *Health) snapshotLocked(host string, s *SiteSeries, windowMins int) SiteStats {
	if windowMins < 1 || windowMins > h.windowMins {
		windowMins = h.windowMins
	}
	nowMinute := minuteOf(h.now())
	fromMinute := nowMinute - int64(windowMins) + 1

	agg := s.aggregate(fromMinute, nowMinute)
	st := SiteStats{
		Host:        host,
		WindowMins:  windowMins,
		Reqs:        agg.Reqs,
		Status2xx:   agg.Status[2],
		Status3xx:   agg.Status[3],
		Status4xx:   agg.Status[4],
		Status5xx:   agg.Status[5],
		UpstreamErr: agg.UpstreamErr,
		Spark:       s.perMinuteReqs(fromMinute, nowMinute),
	}
	if agg.Reqs > 0 {
		st.ReqPerSec = float64(agg.Reqs) / float64(windowMins*60)
		st.Err5xxRatio = float64(agg.Status[5]) / float64(agg.Reqs)
	}
	if agg.Lat.Count() > 0 {
		st.HasLatency = true
		st.P50Sec = agg.Lat.Quantile(0.50)
		st.P95Sec = agg.Lat.Quantile(0.95)
		st.P99Sec = agg.Lat.Quantile(0.99)
	}

	// recentReqs = request count in the last 2 minutes (to detect "Down" without being skewed by
	// the current, still-incomplete minute).
	recent := s.aggregate(nowMinute-1, nowMinute)
	st.classify(h.th, recent.Reqs)
	return st
}

// Prune cleans up sites with no data left in the window (freeing RAM when a host disappears
// entirely). Call it periodically alongside detection prune.
func (h *Health) Prune() {
	h.mu.Lock()
	defer h.mu.Unlock()
	nowMinute := minuteOf(h.now())
	fromMinute := nowMinute - int64(h.windowMins) + 1
	for host, s := range h.sites {
		if h.allow != nil {
			if _, declared := h.allow[host]; declared {
				continue // keep declared/discovered sites visible (Idle) even with no traffic
			}
		}
		if s.aggregate(fromMinute, nowMinute).Reqs == 0 {
			delete(h.sites, host)
		}
	}
}
