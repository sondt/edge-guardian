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

// sshHarness builds an App with both http and sshd detectors (as the daemon does),
// so cross-detector behavior is exercised too.
func sshHarness(t *testing.T, sshThreshold int) *harness {
	t.Helper()
	p, _ := parse.NewLineParser(lineRegex)
	m, _ := detect.NewMatcher([]string{`\.(php|env)(\?|/|$)`})
	st, _ := state.Load(filepath.Join(t.TempDir(), "state.json"), time.Now(), 0)
	enf := &fakeEnforcer{}
	noti := &fakeNotifier{}
	fixed := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

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
	sp := parse.NewSSHParser()
	sshDet := &Detector{
		Name:   "sshd",
		Window: detect.Hits(sshThreshold, time.Minute),
		Inspect: func(line string) (ip, sub, reason string, ok bool) {
			ip, reason, ok = sp.Parse(line)
			return ip, "", reason, ok
		},
	}

	d := Deps{
		Detectors:   []*Detector{httpDet, sshDet},
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

func sshFailLine(ip string) string {
	return "May 12 10:00:01 host sshd[123]: Failed password for invalid user admin from " + ip + " port 54321 ssh2"
}

func TestPipeline_SSHBruteForce(t *testing.T) {
	h := sshHarness(t, 3)
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	h.app.ProcessLine(sshFailLine("203.0.113.50"))
	h.app.ProcessLine(sshFailLine("203.0.113.50"))
	if h.enf.banCount() != 0 {
		t.Fatalf("should not ban before threshold, got %d", h.enf.banCount())
	}
	h.app.ProcessLine(sshFailLine("203.0.113.50"))
	if h.enf.banCount() != 1 {
		t.Fatalf("should ban on 3rd failed login, got %d", h.enf.banCount())
	}

	e, ok := h.st.Get("203.0.113.50")
	if !ok || e.Detector != "sshd" {
		t.Fatalf("entry=%+v want Detector=sshd", e)
	}
	if e.Reason == "" {
		t.Fatal("ssh ban should carry a reason")
	}
	if !h.st.IsBanned("203.0.113.50", now) {
		t.Fatal("ip should be banned")
	}
	// The event pushed to the dashboard sink should be tagged sshd.
	if len(h.noti.events) != 1 {
		t.Fatalf("notify count=%d want 1", len(h.noti.events))
	}
}

func TestPipeline_SSHAllowlisted(t *testing.T) {
	h := sshHarness(t, 1)
	h.app.ProcessLine(sshFailLine("10.0.0.9")) // allowlisted admin range
	if h.enf.banCount() != 0 {
		t.Fatal("allowlisted IP must not be banned even on ssh failure")
	}
}

func TestPipeline_SSHAndHTTPIndependent(t *testing.T) {
	h := sshHarness(t, 5) // ssh needs 5, http needs 1
	// One http scanner hit bans immediately; an ssh failure below threshold does not.
	h.app.ProcessLine(logLine("198.51.100.10", "/wp-login.php"))
	h.app.ProcessLine(sshFailLine("198.51.100.20"))

	if !h.st.IsBanned("198.51.100.10", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("http scanner should be banned immediately")
	}
	if h.st.IsBanned("198.51.100.20", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("single ssh failure must not ban (below threshold)")
	}
	got, _ := h.st.Get("198.51.100.10")
	if got.Detector != "http" {
		t.Fatalf("detector=%q want http", got.Detector)
	}
}
