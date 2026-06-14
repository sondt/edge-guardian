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

// nfHarness builds an App with honeypot + portscan detectors (kernel netfilter LOG).
func nfHarness(t *testing.T, scanThreshold int) *harness {
	t.Helper()
	st, _ := state.Load(filepath.Join(t.TempDir(), "state.json"), time.Now(), 0)
	enf := &fakeEnforcer{}
	noti := &fakeNotifier{}
	fixed := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	hp := parse.NewNetfilterParser("EDGEGUARD-HONEYPOT")
	honeypot := &Detector{
		Name:   "honeypot",
		Window: detect.Hits(1, time.Minute),
		Inspect: func(line string) (ip, sub, reason string, ok bool) {
			ev, matched := hp.Parse(line)
			if !matched {
				return "", "", "", false
			}
			return ev.IP, "", "honeypot port :" + ev.Port, true
		},
	}
	ps := parse.NewNetfilterParser("EDGEGUARD-SCAN")
	portscan := &Detector{
		Name:   "portscan",
		Window: detect.NewDistinct(scanThreshold, time.Minute),
		Inspect: func(line string) (ip, sub, reason string, ok bool) {
			ev, matched := ps.Parse(line)
			if !matched {
				return "", "", "", false
			}
			return ev.IP, ev.Port, "port scan (distinct ports)", true
		},
	}

	d := Deps{
		Detectors:   []*Detector{honeypot, portscan},
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

func scanLineFor(ip, dpt string) string {
	return "host kernel: EDGEGUARD-SCAN IN=eth0 SRC=" + ip + " DST=10.0.0.1 PROTO=TCP SPT=44321 DPT=" + dpt + " SYN"
}

func honeypotLine(ip, dpt string) string {
	return "host kernel: EDGEGUARD-HONEYPOT IN=eth0 SRC=" + ip + " DST=10.0.0.1 PROTO=TCP SPT=5 DPT=" + dpt + " SYN"
}

func TestPipeline_HoneypotInstantBan(t *testing.T) {
	h := nfHarness(t, 10)
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	h.app.ProcessLine(honeypotLine("45.13.22.7", "23"))
	if h.enf.banCount() != 1 {
		t.Fatalf("honeypot should ban on first touch, got %d", h.enf.banCount())
	}
	e, _ := h.st.Get("45.13.22.7")
	if e.Detector != "honeypot" || e.Reason != "honeypot port :23" {
		t.Fatalf("entry=%+v want detector=honeypot reason='honeypot port :23'", e)
	}
	if !h.st.IsBanned("45.13.22.7", now) {
		t.Fatal("should be banned")
	}
}

func TestPipeline_PortScanDistinctPorts(t *testing.T) {
	h := nfHarness(t, 5) // ban at 5 distinct ports

	// Same port hammered repeatedly must NOT trip a distinct-port scan.
	for i := 0; i < 8; i++ {
		h.app.ProcessLine(scanLineFor("203.0.113.99", "22"))
	}
	if h.enf.banCount() != 0 {
		t.Fatalf("repeated same port should not be a scan, got %d", h.enf.banCount())
	}

	// Four MORE distinct ports → 5 distinct total → ban.
	for _, p := range []string{"23", "80", "443", "3306"} {
		h.app.ProcessLine(scanLineFor("203.0.113.99", p))
	}
	if h.enf.banCount() != 1 {
		t.Fatalf("5 distinct ports should ban, got %d", h.enf.banCount())
	}
	e, _ := h.st.Get("203.0.113.99")
	if e.Detector != "portscan" {
		t.Fatalf("detector=%q want portscan", e.Detector)
	}
}

func TestPipeline_PortScanBelowThreshold(t *testing.T) {
	h := nfHarness(t, 10)
	for _, p := range []string{"22", "23", "80"} { // only 3 distinct
		h.app.ProcessLine(scanLineFor("198.51.100.5", p))
	}
	if h.enf.banCount() != 0 {
		t.Fatal("3 distinct ports below threshold 10 must not ban")
	}
}

func TestPipeline_PortScanAllowlisted(t *testing.T) {
	h := nfHarness(t, 2)
	h.app.ProcessLine(scanLineFor("10.0.0.7", "22"))
	h.app.ProcessLine(scanLineFor("10.0.0.7", "23"))
	if h.enf.banCount() != 0 {
		t.Fatal("allowlisted IP must not be banned by port scan")
	}
}
