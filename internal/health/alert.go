package health

import (
	"fmt"
	"sync"
	"time"
)

// AlertConfig controls the alerter's anti-noise logic.
type AlertConfig struct {
	Thresholds Thresholds
	Sustained  time.Duration // how long the condition must hold continuously before alerting
	Cooldown   time.Duration // stay quiet after alerting, to avoid spam
}

// Alert is a state transition that must be sent (firing = degraded/down, !firing = recovered).
type Alert struct {
	Site    string
	Firing  bool
	Reason  string // "5xx" | "latency" | "down"
	Summary string // headline line, e.g. "5xx 12.4% over 5m (threshold 5%)"
	Detail  string // metrics line, e.g. "req/s 240 · p95 1.8s · upstream 3 err"
}

// siteState is a site's alert state carried between Evaluate calls.
type siteState struct {
	pendingSince time.Time // when the bad condition started (zero = not pending)
	firing       bool
	lastFired    time.Time // for applying cooldown
}

// Alerter evaluates site health periodically and emits an Alert when entering/leaving a bad state.
// Sustained ("for duration") + cooldown + hysteresis (exit threshold = half the entry threshold) so
// it doesn't fire on every spike.
type Alerter struct {
	cfg AlertConfig

	mu     sync.Mutex
	states map[string]*siteState
}

// NewAlerter creates an alerter. Sustained/Cooldown <= 0 are set to safe defaults.
func NewAlerter(cfg AlertConfig) *Alerter {
	if cfg.Sustained <= 0 {
		cfg.Sustained = 5 * time.Minute
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 30 * time.Minute
	}
	return &Alerter{cfg: cfg, states: make(map[string]*siteState)}
}

// Evaluate inspects the whole snapshot at now and returns the Alerts to send (firing + recovered).
func (a *Alerter) Evaluate(stats []SiteStats, now time.Time) []Alert {
	a.mu.Lock()
	defer a.mu.Unlock()

	var out []Alert
	for _, s := range stats {
		st := a.states[s.Host]
		if st == nil {
			st = &siteState{}
			a.states[s.Host] = st
		}
		out = a.evalSite(out, s, st, now)
	}
	return out
}

// evalSite runs the state machine for a single site.
func (a *Alerter) evalSite(out []Alert, s SiteStats, st *siteState, now time.Time) []Alert {
	reason, summary, bad := a.condition(s, st.firing)

	if !bad {
		st.pendingSince = time.Time{}
		if st.firing {
			st.firing = false
			out = append(out, Alert{
				Site: s.Host, Firing: false, Reason: "recovered",
				Summary: recoveredSummary(s), Detail: detailLine(s),
			})
		}
		return out
	}

	// The bad condition currently holds.
	if st.firing {
		return out // already alerted, wait for recovery (no spam)
	}
	if st.pendingSince.IsZero() {
		st.pendingSince = now
	}
	if now.Sub(st.pendingSince) < a.cfg.Sustained {
		return out // not yet "sustained" long enough
	}
	if !st.lastFired.IsZero() && now.Sub(st.lastFired) < a.cfg.Cooldown {
		return out // still within cooldown
	}
	st.firing = true
	st.lastFired = now
	st.pendingSince = time.Time{}
	out = append(out, Alert{
		Site: s.Host, Firing: true, Reason: reason, Summary: summary, Detail: detailLine(s),
	})
	return out
}

// condition returns (reason, summary, bad). firing=true → use the EXIT threshold (relaxed, half the
// entry threshold) for hysteresis: once alerting, only consider it cleared when it drops well below the threshold.
func (a *Alerter) condition(s SiteStats, firing bool) (reason, summary string, bad bool) {
	th := a.cfg.Thresholds
	errLimit := th.Err5xxRatio
	p95Limit := th.P95Sec
	if firing {
		errLimit /= 2
		p95Limit /= 2
	}

	// Down has the highest priority.
	if s.Status == "Down" {
		return "down", fmt.Sprintf("Site down — no requests reaching %s", s.Host), true
	}
	if s.Reqs > 0 && th.Err5xxRatio > 0 && s.Err5xxRatio > errLimit {
		return "5xx", fmt.Sprintf("5xx %.1f%% (threshold %.0f%%)",
			s.Err5xxRatio*100, th.Err5xxRatio*100), true
	}
	if th.P95Sec > 0 && s.HasLatency && s.P95Sec > p95Limit {
		return "latency", fmt.Sprintf("p95 %s (threshold %s)",
			humanLatency(s.P95Sec), humanLatency(th.P95Sec)), true
	}
	return "", "", false
}

func recoveredSummary(s SiteStats) string {
	if s.Reqs == 0 {
		return fmt.Sprintf("Recovered — %s", s.Host)
	}
	return fmt.Sprintf("Recovered — %s · 5xx back to %.1f%%", s.Host, s.Err5xxRatio*100)
}

func detailLine(s SiteStats) string {
	d := fmt.Sprintf("req/s %.0f", s.ReqPerSec)
	if s.HasLatency {
		d += " · p95 " + humanLatency(s.P95Sec)
	}
	if s.UpstreamErr > 0 {
		d += fmt.Sprintf(" · upstream %d err", s.UpstreamErr)
	}
	return d
}

// humanLatency renders seconds in a readable form: "820ms" or "1.8s".
func humanLatency(sec float64) string {
	if sec < 1 {
		return fmt.Sprintf("%dms", int(sec*1000+0.5))
	}
	return fmt.Sprintf("%.1fs", sec)
}
