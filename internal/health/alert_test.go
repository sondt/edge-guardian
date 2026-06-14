package health

import (
	"testing"
	"time"
)

func degradedStat(host string, err5xx float64) SiteStats {
	return SiteStats{Host: host, Reqs: 1000, ReqPerSec: 100, Err5xxRatio: err5xx, Status: "Healthy"}
}

func alerterCfg() AlertConfig {
	return AlertConfig{
		Thresholds: Thresholds{Err5xxRatio: 0.05, P95Sec: 2.0},
		Sustained:  5 * time.Minute,
		Cooldown:   30 * time.Minute,
	}
}

func TestAlerter_SustainedBeforeFiring(t *testing.T) {
	a := NewAlerter(alerterCfg())
	t0 := base
	bad := []SiteStats{degradedStat("x.com", 0.12)}

	// First evaluation: condition true but not sustained yet.
	if al := a.Evaluate(bad, t0); len(al) != 0 {
		t.Fatalf("should not fire immediately, got %v", al)
	}
	// 3 min later: still within sustained window.
	if al := a.Evaluate(bad, t0.Add(3*time.Minute)); len(al) != 0 {
		t.Fatalf("should not fire before sustained, got %v", al)
	}
	// 5 min later: fires.
	al := a.Evaluate(bad, t0.Add(5*time.Minute))
	if len(al) != 1 || !al[0].Firing || al[0].Reason != "5xx" {
		t.Fatalf("should fire after sustained: %+v", al)
	}
}

func TestAlerter_NoReFireWhileFiring(t *testing.T) {
	a := NewAlerter(alerterCfg())
	bad := []SiteStats{degradedStat("x.com", 0.12)}
	a.Evaluate(bad, base)
	al := a.Evaluate(bad, base.Add(5*time.Minute))
	if len(al) != 1 {
		t.Fatalf("expected first fire, got %v", al)
	}
	// Still bad later — must NOT re-fire.
	if al := a.Evaluate(bad, base.Add(10*time.Minute)); len(al) != 0 {
		t.Fatalf("must not re-fire while firing, got %v", al)
	}
}

func TestAlerter_RecoveryEmitsResolved(t *testing.T) {
	a := NewAlerter(alerterCfg())
	bad := []SiteStats{degradedStat("x.com", 0.12)}
	a.Evaluate(bad, base)
	a.Evaluate(bad, base.Add(5*time.Minute)) // fires

	good := []SiteStats{degradedStat("x.com", 0.001)} // 0.1% < exit threshold (2.5%)
	al := a.Evaluate(good, base.Add(8*time.Minute))
	if len(al) != 1 || al[0].Firing {
		t.Fatalf("should emit resolved: %+v", al)
	}
}

func TestAlerter_Hysteresis(t *testing.T) {
	a := NewAlerter(alerterCfg())
	bad := []SiteStats{degradedStat("x.com", 0.12)}
	a.Evaluate(bad, base)
	a.Evaluate(bad, base.Add(5*time.Minute)) // fires (entry threshold 5%)

	// Drop to 4% — below entry (5%) but ABOVE exit (2.5%): must stay firing, no resolve.
	mid := []SiteStats{degradedStat("x.com", 0.04)}
	if al := a.Evaluate(mid, base.Add(8*time.Minute)); len(al) != 0 {
		t.Fatalf("hysteresis: 4%% should keep firing (exit=2.5%%), got %v", al)
	}
	// Drop to 1% — below exit: resolves.
	good := []SiteStats{degradedStat("x.com", 0.01)}
	if al := a.Evaluate(good, base.Add(9*time.Minute)); len(al) != 1 || al[0].Firing {
		t.Fatalf("should resolve below exit threshold: %v", al)
	}
}

func TestAlerter_Cooldown(t *testing.T) {
	a := NewAlerter(alerterCfg())
	bad := []SiteStats{degradedStat("x.com", 0.12)}
	good := []SiteStats{degradedStat("x.com", 0.001)}

	a.Evaluate(bad, base)
	a.Evaluate(bad, base.Add(5*time.Minute))  // fires at t=5m
	a.Evaluate(good, base.Add(6*time.Minute)) // resolves at t=6m

	// Degrade again and sustain — but still within cooldown (30m from the t=5m fire) → no fire.
	a.Evaluate(bad, base.Add(7*time.Minute))
	if al := a.Evaluate(bad, base.Add(20*time.Minute)); len(al) != 0 {
		t.Fatalf("must stay silent within cooldown, got %v", al)
	}
	// Cooldown ends at t=35m; the condition has been bad+sustained since t=7m, so the
	// first eval past cooldown fires again.
	al := a.Evaluate(bad, base.Add(40*time.Minute))
	if len(al) != 1 || !al[0].Firing {
		t.Fatalf("should fire again after cooldown: %v", al)
	}
}

func TestAlerter_DownTakesPriority(t *testing.T) {
	a := NewAlerter(alerterCfg())
	down := []SiteStats{{Host: "x.com", Reqs: 500, Status: "Down"}}
	a.Evaluate(down, base)
	al := a.Evaluate(down, base.Add(5*time.Minute))
	if len(al) != 1 || al[0].Reason != "down" {
		t.Fatalf("down should fire with reason 'down': %+v", al)
	}
}

func TestAlerter_LatencyCondition(t *testing.T) {
	a := NewAlerter(alerterCfg())
	slow := []SiteStats{{Host: "x.com", Reqs: 100, ReqPerSec: 10, HasLatency: true, P95Sec: 3.5, Status: "Healthy"}}
	a.Evaluate(slow, base)
	al := a.Evaluate(slow, base.Add(5*time.Minute))
	if len(al) != 1 || al[0].Reason != "latency" {
		t.Fatalf("p95 over threshold should fire latency: %+v", al)
	}
}

func TestAlerter_IdleNeverFires(t *testing.T) {
	a := NewAlerter(alerterCfg())
	idle := []SiteStats{{Host: "x.com", Reqs: 0, Status: "Idle"}}
	for i := 0; i < 5; i++ {
		if al := a.Evaluate(idle, base.Add(time.Duration(i)*5*time.Minute)); len(al) != 0 {
			t.Fatalf("idle site must never alert, got %v", al)
		}
	}
}

func TestHumanLatency(t *testing.T) {
	cases := map[float64]string{0.82: "820ms", 1.8: "1.8s", 0.005: "5ms", 2.0: "2.0s"}
	for in, want := range cases {
		if got := humanLatency(in); got != want {
			t.Errorf("humanLatency(%v)=%q want %q", in, got, want)
		}
	}
}
