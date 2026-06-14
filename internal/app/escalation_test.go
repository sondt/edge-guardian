package app

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/sondt/edge-guardian/internal/allow"
	"github.com/sondt/edge-guardian/internal/detect"
	"github.com/sondt/edge-guardian/internal/parse"
	"github.com/sondt/edge-guardian/internal/state"
)

func TestBanDurationFor(t *testing.T) {
	esc := []time.Duration{time.Hour, 24 * time.Hour, 720 * time.Hour}
	flat := 48 * time.Hour

	// No escalation → flat regardless of offense.
	if got := banDurationFor(0, nil, flat); got != flat {
		t.Fatalf("flat 0 = %v want %v", got, flat)
	}
	if got := banDurationFor(5, nil, flat); got != flat {
		t.Fatalf("flat 5 = %v want %v", got, flat)
	}
	// Escalation by offense index, capped at last.
	cases := []struct {
		idx  int
		want time.Duration
	}{
		{0, time.Hour}, {1, 24 * time.Hour}, {2, 720 * time.Hour}, {3, 720 * time.Hour}, {99, 720 * time.Hour}, {-1, time.Hour},
	}
	for _, c := range cases {
		if got := banDurationFor(c.idx, esc, flat); got != c.want {
			t.Fatalf("idx %d = %v want %v", c.idx, got, c.want)
		}
	}
}

// escalationHarness builds an App with a mutable clock + escalation policy.
func escalationHarness(t *testing.T, esc []time.Duration, memory time.Duration, clock *time.Time) *harness {
	t.Helper()
	p, _ := parse.NewLineParser(lineRegex)
	m, _ := detect.NewMatcher([]string{`/(wp-login|xmlrpc)`})
	st, _ := state.Load(filepath.Join(t.TempDir(), "state.json"), *clock, memory)
	enf := &fakeEnforcer{}
	noti := &fakeNotifier{}
	httpDet := &Detector{
		Name:   "http",
		Window: detect.Hits(1, time.Minute),
		Inspect: func(line string) (ip, sub, reason string, ok bool) {
			ev, matched := p.Parse(line)
			if !matched || !m.IsBad(ev.URI) {
				return "", "", "", false
			}
			return ev.IP, "", ev.URI, true
		},
	}
	d := Deps{
		Detectors:        []*Detector{httpDet},
		Allow:            allow.New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}),
		State:            st,
		Enforcer:         enf,
		Notifier:         noti,
		Escalation:       esc,
		EscalationMemory: memory,
		Logger:           discardLogger(),
		Now:              func() time.Time { return *clock },
	}
	return &harness{app: New(d), enf: enf, noti: noti, st: st}
}

func TestEscalatingBan(t *testing.T) {
	esc := []time.Duration{time.Hour, 24 * time.Hour, 720 * time.Hour}
	memory := 30 * 24 * time.Hour
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := now

	h := escalationHarness(t, esc, memory, &clock)

	// 1st offense → 1h.
	h.app.ProcessLine(logLine("203.0.113.7", "/wp-login.php"))
	if got := h.enf.banDurs[0]; got != time.Hour {
		t.Fatalf("1st ban dur=%v want 1h", got)
	}

	// Advance past expiry (but within memory) → re-offend → 2nd offense = 24h.
	clock = now.Add(2 * time.Hour)
	h.app.ProcessLine(logLine("203.0.113.7", "/xmlrpc.php"))
	if len(h.enf.banDurs) != 2 || h.enf.banDurs[1] != 24*time.Hour {
		t.Fatalf("2nd ban durs=%v want second=24h", h.enf.banDurs)
	}

	// Advance again → 3rd offense = 720h.
	clock = now.Add(28 * time.Hour)
	h.app.ProcessLine(logLine("203.0.113.7", "/wp-login.php"))
	if h.enf.banDurs[2] != 720*time.Hour {
		t.Fatalf("3rd ban dur=%v want 720h", h.enf.banDurs[2])
	}

	// 4th → capped at last (720h).
	clock = now.Add(28*time.Hour + 721*time.Hour)
	h.app.ProcessLine(logLine("203.0.113.7", "/wp-login.php"))
	if h.enf.banDurs[3] != 720*time.Hour {
		t.Fatalf("4th ban dur=%v want 720h (capped)", h.enf.banDurs[3])
	}
}

func TestEscalation_MemoryForgetsOldOffenders(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	memory := 24 * time.Hour
	path := filepath.Join(t.TempDir(), "s.json")

	st, _ := state.Load(path, now, memory)
	// Ban that expired 2 hours ago; memory is 24h → should still be remembered.
	st.Ban("1.2.3.4", "http", "/x", 1, now.Add(-3*time.Hour), now.Add(-2*time.Hour))
	st.Save()

	// Reload within memory window → offender retained.
	s2, _ := state.Load(path, now, memory)
	if e, ok := s2.Get("1.2.3.4"); !ok || e.BanCount != 1 {
		t.Fatalf("offender should be remembered within memory window: %+v ok=%v", e, ok)
	}

	// Reload far past memory window → forgotten.
	s3, _ := state.Load(path, now.Add(48*time.Hour), memory)
	if _, ok := s3.Get("1.2.3.4"); ok {
		t.Fatal("offender should be forgotten past memory window")
	}
}
