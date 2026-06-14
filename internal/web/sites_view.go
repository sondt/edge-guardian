package web

import "fmt"

// siteView is a SiteHealth prepared for rendering: humanized fields + status styling so
// the template stays logic-free. Mirrors banView/eventView.
type siteView struct {
	Host        string
	Status      string
	StatusClass string // "is-healthy" | "is-degraded" | "is-down" | "is-idle"
	StatusDot   string // ● ▲ ✕ ○
	ReqPerSec   string
	Err5xx      string
	HasLatency  bool
	P95         string
	UpstreamErr string // "" when zero
	SparkPoints string // SVG polyline points
}

const sparkW, sparkH = 120.0, 26.0

func toSiteView(s SiteHealth) siteView {
	v := siteView{
		Host:        s.Host,
		Status:      s.Status,
		StatusClass: statusClass(s.Status),
		StatusDot:   statusDot(s.Status),
		ReqPerSec:   fmtReqPerSec(s.ReqPerSec),
		Err5xx:      fmt.Sprintf("%.1f%%", s.Err5xxPct),
		HasLatency:  s.HasLatency,
		SparkPoints: sparkPath(s.Spark, sparkW, sparkH),
	}
	if s.HasLatency {
		v.P95 = fmtLatency(s.P95Sec)
	}
	if s.UpstreamErr > 0 {
		v.UpstreamErr = fmt.Sprintf("%d err", s.UpstreamErr)
	}
	return v
}

func toSiteViews(sites []SiteHealth) []siteView {
	out := make([]siteView, 0, len(sites))
	for _, s := range sites {
		out = append(out, toSiteView(s))
	}
	return out
}

func statusClass(status string) string {
	switch status {
	case "Healthy":
		return "is-healthy"
	case "Degraded":
		return "is-degraded"
	case "Down":
		return "is-down"
	default:
		return "is-idle"
	}
}

func statusDot(status string) string {
	switch status {
	case "Healthy":
		return "●"
	case "Degraded":
		return "▲"
	case "Down":
		return "✕"
	default:
		return "○"
	}
}

func fmtReqPerSec(r float64) string {
	if r >= 10 {
		return fmt.Sprintf("%.0f", r)
	}
	return fmt.Sprintf("%.1f", r)
}

func fmtLatency(sec float64) string {
	if sec < 1 {
		return fmt.Sprintf("%dms", int(sec*1000+0.5))
	}
	return fmt.Sprintf("%.1fs", sec)
}

// SiteSummary is the Overview "Site health" readout: overall state + how many sites are
// degraded/down, computed from the per-site list.
type SiteSummary struct {
	Total    int
	Degraded int
	Down     int
	State    string // "Healthy" | "Degraded" | "Down" | "—" (no sites)
}

// siteSummaryClass maps the overall site state to a CSS modifier for the readout tone.
func siteSummaryClass(s SiteSummary) string {
	switch s.State {
	case "Down":
		return "is-down"
	case "Degraded":
		return "is-degraded"
	case "Healthy":
		return "is-healthy"
	default:
		return "is-idle"
	}
}

func summarizeSites(sites []SiteHealth) SiteSummary {
	s := SiteSummary{Total: len(sites)}
	for _, h := range sites {
		switch h.Status {
		case "Degraded":
			s.Degraded++
		case "Down":
			s.Down++
		}
	}
	switch {
	case s.Total == 0:
		s.State = "—"
	case s.Down > 0:
		s.State = "Down"
	case s.Degraded > 0:
		s.State = "Degraded"
	default:
		s.State = "Healthy"
	}
	return s
}
