package app

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/sondt/edge-guardian/internal/allow"
	"github.com/sondt/edge-guardian/internal/config"
	"github.com/sondt/edge-guardian/internal/detect"
	"github.com/sondt/edge-guardian/internal/parse"
	"github.com/sondt/edge-guardian/internal/state"
)

// lineRegexUA captures the trailing user-agent (combined log format) so the bad-bot
// detector can read it.
const lineRegexUA = `^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?:\S+) (?P<uri>\S+)[^"]*" \d+ \S+ "[^"]*" "(?P<ua>[^"]*)"`

// logLineUA builds a combined-format access line with an explicit user-agent.
func logLineUA(ip, uri, ua string) string {
	return ip + ` - - [01/Jan/2024:00:00:00 +0000] "GET ` + uri + ` HTTP/1.1" 404 0 "-" "` + ua + `"`
}

func badbotHarness(t *testing.T, threshold int) *harness {
	t.Helper()
	p, err := parse.NewLineParser(lineRegexUA)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasUA() {
		t.Fatal("test regex should capture ua")
	}
	m, _ := detect.NewMatcher(config.DefaultBadBotPatterns())
	st, _ := state.Load(filepath.Join(t.TempDir(), "state.json"), time.Now(), 0)
	enf := &fakeEnforcer{}
	noti := &fakeNotifier{}
	fixed := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	botDet := &Detector{
		Name:   "badbot",
		Window: detect.Hits(threshold, time.Minute),
		Inspect: func(line string) (ip, sub, reason string, ok bool) {
			ev, matched := p.Parse(line)
			if !matched || ev.UA == "" || !m.IsBad(ev.UA) {
				return "", "", "", false
			}
			return ev.IP, "", "bad bot UA: " + ev.UA, true
		},
	}

	d := Deps{
		Detectors:   []*Detector{botDet},
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

func TestPipeline_BadBotBansOnScannerUA(t *testing.T) {
	h := badbotHarness(t, 1)
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	h.app.ProcessLine(logLineUA("203.0.113.30", "/", "sqlmap/1.7.2#stable (https://sqlmap.org)"))
	if h.enf.banCount() != 1 {
		t.Fatalf("a sqlmap UA should ban immediately, got %d", h.enf.banCount())
	}
	e, ok := h.st.Get("203.0.113.30")
	if !ok || e.Detector != "badbot" {
		t.Fatalf("entry=%+v want Detector=badbot", e)
	}
	if !h.st.IsBanned("203.0.113.30", now) {
		t.Fatal("ip should be banned")
	}
}

func TestPipeline_BadBotIgnoresRealBrowser(t *testing.T) {
	h := badbotHarness(t, 1)
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
	h.app.ProcessLine(logLineUA("203.0.113.31", "/index.html", ua))
	h.app.ProcessLine(logLineUA("203.0.113.31", "/about", "Mozilla/5.0 (compatible; Googlebot/2.1)"))
	if h.enf.banCount() != 0 {
		t.Fatal("real browser / Googlebot must not be banned")
	}
}

func TestPipeline_BadBotAllowlisted(t *testing.T) {
	h := badbotHarness(t, 1)
	h.app.ProcessLine(logLineUA("10.0.0.7", "/", "nikto/2.5.0"))
	if h.enf.banCount() != 0 {
		t.Fatal("allowlisted IP must not be banned even with a scanner UA")
	}
}

func TestPipeline_BadBotThreshold(t *testing.T) {
	h := badbotHarness(t, 3)
	for i := 0; i < 2; i++ {
		h.app.ProcessLine(logLineUA("198.51.100.40", "/", "python-requests/2.31.0"))
	}
	if h.enf.banCount() != 0 {
		t.Fatal("should not ban before threshold")
	}
	h.app.ProcessLine(logLineUA("198.51.100.40", "/", "python-requests/2.31.0"))
	if h.enf.banCount() != 1 {
		t.Fatalf("should ban on 3rd hit, got %d", h.enf.banCount())
	}
}

func TestPipeline_BadBotEmptyUAIgnored(t *testing.T) {
	h := badbotHarness(t, 1)
	h.app.ProcessLine(logLineUA("198.51.100.41", "/health", "-"))
	if h.enf.banCount() != 0 {
		t.Fatal("empty/'-' UA must not trip the default bad-bot set")
	}
}
