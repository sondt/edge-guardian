package app

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/sondt/edge-guardian/internal/allow"
	"github.com/sondt/edge-guardian/internal/health"
	"github.com/sondt/edge-guardian/internal/parse"
	"github.com/sondt/edge-guardian/internal/state"
)

var base = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

func healthJSON(host string, status int, rt float64) string {
	return fmt.Sprintf(`{"host":%q,"remote_addr":"203.0.113.1","uri":"/","status":%d,"request_time":%v,"bytes":100}`,
		host, status, rt)
}

// healthApp builds an App with only the health branch wired (no detectors), driven by a
// shared controllable clock.
func healthApp(t *testing.T, cur *time.Time) (*App, *fakeNotifier, *health.Health) {
	t.Helper()
	nowf := func() time.Time { return *cur }
	th := health.Thresholds{Err5xxRatio: 0.05, P95Sec: 2.0}
	h := health.New(health.Config{WindowMins: 30, Thresholds: th, Now: nowf})
	al := health.NewAlerter(health.AlertConfig{Thresholds: th, Sustained: 5 * time.Minute, Cooldown: 30 * time.Minute})
	parser, _ := parse.NewLineParser(lineRegex)
	st, _ := state.Load(filepath.Join(t.TempDir(), "state.json"), *cur, 0)
	noti := &fakeNotifier{}

	d := Deps{
		Allow:             allow.New([]netip.Prefix{}),
		State:             st,
		Enforcer:          &fakeEnforcer{},
		Notifier:          noti,
		Health:            h,
		HealthAlerter:     al,
		HealthParser:      parser,
		HealthWindow:      30,
		HealthAlertWindow: 5,
		Logger:            discardLogger(),
		Now:               nowf,
	}
	return New(d), noti, h
}

func TestHealth_ObserveThroughApp(t *testing.T) {
	cur := base
	app, _, h := healthApp(t, &cur)

	for i := 0; i < 50; i++ {
		app.observeHealth(healthJSON("site.com", 200, 0.1))
	}
	app.observeHealth(healthJSON("site.com", 503, 0.1))
	// A non-JSON garbage line must be ignored by the health branch.
	app.observeHealth("garbage not a log line")

	st, ok := h.Snapshot("site.com", 30)
	if !ok || st.Reqs != 51 {
		t.Fatalf("snapshot=%+v ok=%v want 51 reqs", st, ok)
	}
	if st.Status5xx != 1 {
		t.Fatalf("5xx=%d want 1", st.Status5xx)
	}
}

func TestHealth_AlertFiresAndRecovers(t *testing.T) {
	cur := base
	app, noti, _ := healthApp(t, &cur)

	observeMinute := func(host string, pct5xx int) {
		for i := 0; i < 100; i++ {
			status := 200
			if i < pct5xx {
				status = 503
			}
			app.observeHealth(healthJSON(host, status, 0.1))
		}
	}

	// 6 minutes of 12% 5xx → should fire once sustained (5m).
	for m := 0; m <= 6; m++ {
		cur = base.Add(time.Duration(m) * time.Minute)
		observeMinute("bad.com", 12)
		app.evaluateHealth()
	}
	noti.mu.Lock()
	fired := len(noti.healthEvents)
	var firstFiring bool
	if fired > 0 {
		firstFiring = noti.healthEvents[0].Firing
	}
	noti.mu.Unlock()
	if fired == 0 || !firstFiring {
		t.Fatalf("expected a firing health alert, got %d events", fired)
	}

	// Now 6 minutes of healthy traffic → window flushes → recovered.
	for m := 7; m <= 13; m++ {
		cur = base.Add(time.Duration(m) * time.Minute)
		observeMinute("bad.com", 0)
		app.evaluateHealth()
	}
	noti.mu.Lock()
	defer noti.mu.Unlock()
	last := noti.healthEvents[len(noti.healthEvents)-1]
	if last.Firing {
		t.Fatalf("expected a recovered (Firing=false) alert last, got %+v", last)
	}
}

func TestHealth_DisabledIsNoop(t *testing.T) {
	// No health in Deps → observeHealth/evaluateHealth must be safe no-ops.
	h := newHarness(t, 1, false)
	h.app.observeHealth(healthJSON("x", 500, 1))
	h.app.evaluateHealth()
	if len(h.noti.healthEvents) != 0 {
		t.Fatal("health disabled must not notify")
	}
}
