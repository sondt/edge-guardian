package web

import (
	"strings"
	"testing"
	"time"
)

func TestHumanizeUntil(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		at   time.Time
		want string
	}{
		{"zero", time.Time{}, "—"},
		{"past", now.Add(-time.Hour), "expired"},
		{"days", now.Add(6*24*time.Hour + 23*time.Hour), "in 6d23h"},
		{"hours", now.Add(2*time.Hour + 30*time.Minute), "in 2h30m"},
		{"minutes", now.Add(14 * time.Minute), "in 14m"},
		{"sub-minute", now.Add(30 * time.Second), "in <1m"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := humanizeUntil(c.at, now); got != c.want {
				t.Fatalf("humanizeUntil(%v) = %q, want %q", c.at, got, c.want)
			}
		})
	}
}

func TestFilterBans(t *testing.T) {
	now := time.Now()
	bans := []Ban{
		{IP: "185.1.2.3", Detector: "http", ASN: "AS4837", Country: "CN", FirstSeen: now},
		{IP: "92.4.5.6", Detector: "portscan", ASN: "AS1299", Country: "RU", FirstSeen: now.Add(-time.Minute)},
		{IP: "45.7.8.9", Detector: "http", ASN: "AS7922", Country: "US", FirstSeen: now.Add(-2 * time.Minute)},
	}

	// Search by IP fragment.
	got := filterBans(bans, "92.4", "", now)
	if len(got) != 1 || got[0].IP != "92.4.5.6" {
		t.Fatalf("search by ip failed: %+v", got)
	}

	// Filter by detector.
	got = filterBans(bans, "", "http", now)
	if len(got) != 2 {
		t.Fatalf("detector filter want 2, got %d", len(got))
	}

	// Search by ASN, case-insensitive.
	got = filterBans(bans, "as1299", "", now)
	if len(got) != 1 || got[0].ASN != "AS1299" {
		t.Fatalf("asn search failed: %+v", got)
	}

	// No filter → all, newest first.
	got = filterBans(bans, "", "", now)
	if len(got) != 3 || got[0].IP != "185.1.2.3" {
		t.Fatalf("sort newest-first failed: %+v", got)
	}
}

func TestDetectorOptions(t *testing.T) {
	bans := []Ban{
		{Detector: "http"}, {Detector: "portscan"}, {Detector: "http"}, {Detector: ""},
	}
	opts := detectorOptions(bans)
	if len(opts) != 2 || opts[0] != "http" || opts[1] != "portscan" {
		t.Fatalf("detectorOptions = %v", opts)
	}
}

func TestSparkPath(t *testing.T) {
	if got := sparkPath(nil, 100, 24); got != "" {
		t.Fatalf("empty series should give empty path, got %q", got)
	}
	if got := sparkPath([]int{0, 0, 0}, 100, 24); got != "" {
		t.Fatalf("flat-zero series should give empty path, got %q", got)
	}
	path := sparkPath([]int{0, 5, 10}, 100, 24)
	if !strings.Contains(path, "0.0,24.0") {
		t.Fatalf("first point should sit on baseline: %q", path)
	}
	if !strings.Contains(path, "100.0,0.0") {
		t.Fatalf("peak point should reach the top: %q", path)
	}
}

func TestOriginText(t *testing.T) {
	cases := []struct{ country, asn, want string }{
		{"CN", "AS4837", "CN · AS4837"},
		{"", "AS1299", "AS1299"},
		{"US", "", "US"},
		{"", "", "—"},
	}
	for _, c := range cases {
		if got := originText(c.country, c.asn); got != c.want {
			t.Fatalf("originText(%q,%q) = %q, want %q", c.country, c.asn, got, c.want)
		}
	}
}

func TestPct(t *testing.T) {
	if pct(0.713) != "71%" {
		t.Fatalf("pct(0.713) = %q", pct(0.713))
	}
	if pct(1.0) != "100%" {
		t.Fatalf("pct(1.0) = %q", pct(1.0))
	}
}

func TestCSRFRoundTrip(t *testing.T) {
	tok, err := newCSRFToken()
	if err != nil {
		t.Fatalf("newCSRFToken: %v", err)
	}
	if len(tok) < 40 {
		t.Fatalf("token too short: %q", tok)
	}
	a, _ := newCSRFToken()
	b, _ := newCSRFToken()
	if a == b {
		t.Fatal("tokens should be unique")
	}
}

func TestAuthVerifyConstantTimeShape(t *testing.T) {
	a := &authenticator{} // not configured
	if a.verify("admin", "x") {
		t.Fatal("unconfigured authenticator must reject")
	}
}

func TestIsLoopbackListen(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"127.0.0.1:8787", true},
		{"localhost:8787", true},
		{"[::1]:8787", true},
		{"0.0.0.0:8787", false},
		{"192.168.1.10:8787", false},
	}
	for _, c := range cases {
		if got := isLoopbackListen(c.in); got != c.want {
			t.Fatalf("isLoopbackListen(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
