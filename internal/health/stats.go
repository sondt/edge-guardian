package health

import "sort"

// Thresholds are the thresholds used to classify a site's status on the dashboard (matching the
// alert thresholds in the config [health]).
type Thresholds struct {
	Err5xxRatio float64 // 0..1; exceeding = degraded
	P95Sec      float64 // seconds; 0 = don't consider latency
}

// SiteStats is a snapshot of one site's health over the window — the read model for dashboard + alert.
type SiteStats struct {
	Host       string
	WindowMins int

	Reqs      uint64
	ReqPerSec float64

	Status2xx uint64
	Status3xx uint64
	Status4xx uint64
	Status5xx uint64

	Err5xxRatio float64 // 0..1

	HasLatency bool
	P50Sec     float64
	P95Sec     float64
	P99Sec     float64

	UpstreamErr uint64

	Spark  []int  // requests per minute (old → new)
	Status string // "Healthy" | "Degraded" | "Down" | "Idle"
}

// classify sets the Status field based on thresholds and recent traffic.
//   - Idle  : no requests in the window (site quiet, no alarm).
//   - Down  : traffic in the window but ~0 in the last 2 minutes (dropped to 0).
//   - Degraded: exceeds the 5xx or p95 threshold.
//   - Healthy: everything else.
func (s *SiteStats) classify(th Thresholds, recentReqs uint64) {
	switch {
	case s.Reqs == 0:
		s.Status = "Idle"
	case recentReqs == 0:
		s.Status = "Down"
	case s.Err5xxRatio > th.Err5xxRatio:
		s.Status = "Degraded"
	case th.P95Sec > 0 && s.HasLatency && s.P95Sec > th.P95Sec:
		s.Status = "Degraded"
	default:
		s.Status = "Healthy"
	}
}

// byHost sorts a list of SiteStats by host (stable for the dashboard).
func byHost(stats []SiteStats) {
	sort.Slice(stats, func(i, j int) bool { return stats[i].Host < stats[j].Host })
}
