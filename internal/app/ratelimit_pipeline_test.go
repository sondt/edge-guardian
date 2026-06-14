package app

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/sondt/edge-guardian/internal/allow"
	"github.com/sondt/edge-guardian/internal/detect"
	"github.com/sondt/edge-guardian/internal/parse"
	"github.com/sondt/edge-guardian/internal/state"
)

// rateHarness builds an App with a single ratelimit detector that counts EVERY parsed
// request per IP (no signature), tripping at the given threshold.
func rateHarness(t *testing.T, threshold int) *harness {
	t.Helper()
	p, _ := parse.NewLineParser(lineRegex)
	st, _ := state.Load(filepath.Join(t.TempDir(), "state.json"), time.Now(), 0)
	enf := &fakeEnforcer{}
	noti := &fakeNotifier{}
	fixed := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	reason := fmt.Sprintf("rate abuse (>%d req / 10s)", threshold)

	rateDet := &Detector{
		Name:   "ratelimit",
		Window: detect.Hits(threshold, 10*time.Second),
		Inspect: func(line string) (ip, sub, r string, ok bool) {
			ev, matched := p.Parse(line)
			if !matched {
				return "", "", "", false
			}
			return ev.IP, "", reason, true
		},
	}

	d := Deps{
		Detectors:   []*Detector{rateDet},
		Allow:       allow.New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}),
		State:       st,
		Enforcer:    enf,
		Notifier:    noti,
		BanDuration: time.Hour,
		Logger:      discardLogger(),
		Now:         func() time.Time { return fixed },
	}
	return &harness{app: New(d), enf: enf, noti: noti, st: st}
}

func TestPipeline_RateLimitBansFlood(t *testing.T) {
	h := rateHarness(t, 5)
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Any URL counts — a flood of normal-looking requests from one IP trips it.
	for i := 0; i < 4; i++ {
		h.app.ProcessLine(logLine("203.0.113.60", "/index.html"))
	}
	if h.enf.banCount() != 0 {
		t.Fatalf("should not ban before threshold, got %d", h.enf.banCount())
	}
	h.app.ProcessLine(logLine("203.0.113.60", "/api/data"))
	if h.enf.banCount() != 1 {
		t.Fatalf("should ban on the 5th request, got %d", h.enf.banCount())
	}
	e, ok := h.st.Get("203.0.113.60")
	if !ok || e.Detector != "ratelimit" {
		t.Fatalf("entry=%+v want Detector=ratelimit", e)
	}
	if !h.st.IsBanned("203.0.113.60", now) {
		t.Fatal("ip should be banned")
	}
}

func TestPipeline_RateLimitAllowlisted(t *testing.T) {
	h := rateHarness(t, 3)
	for i := 0; i < 10; i++ {
		h.app.ProcessLine(logLine("10.0.0.20", "/")) // allowlisted proxy/CDN
	}
	if h.enf.banCount() != 0 {
		t.Fatal("allowlisted IP must never be rate-banned (CDN/proxy protection)")
	}
}

func TestPipeline_RateLimitPerIPIndependent(t *testing.T) {
	h := rateHarness(t, 3)
	// Three distinct IPs each below threshold — none should be banned.
	h.app.ProcessLine(logLine("198.51.100.1", "/"))
	h.app.ProcessLine(logLine("198.51.100.2", "/"))
	h.app.ProcessLine(logLine("198.51.100.1", "/"))
	h.app.ProcessLine(logLine("198.51.100.3", "/"))
	if h.enf.banCount() != 0 {
		t.Fatal("the rate window must be per-IP — spread traffic must not ban")
	}
}

func TestPipeline_RateLimitWindowExpiry(t *testing.T) {
	h := rateHarness(t, 3)
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// Override the clock so requests fall outside the 10s window.
	cur := base
	h.app.now = func() time.Time { return cur }

	h.app.ProcessLine(logLine("203.0.113.61", "/")) // t=0
	cur = base.Add(20 * time.Second)
	h.app.ProcessLine(logLine("203.0.113.61", "/")) // t=20s, first is expired
	cur = base.Add(40 * time.Second)
	h.app.ProcessLine(logLine("203.0.113.61", "/")) // t=40s
	if h.enf.banCount() != 0 {
		t.Fatal("requests spaced beyond the window must not accumulate to a ban")
	}
}
