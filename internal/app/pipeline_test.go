package app

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sondt/edge-guardian/internal/allow"
	"github.com/sondt/edge-guardian/internal/detect"
	"github.com/sondt/edge-guardian/internal/notify"
	"github.com/sondt/edge-guardian/internal/parse"
	"github.com/sondt/edge-guardian/internal/state"
)

const lineRegex = `^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?:\S+) (?P<uri>\S+)[^"]*" `

// fakeEnforcer records Ban/Unban calls.
type fakeEnforcer struct {
	mu       sync.Mutex
	bans     []netip.Addr
	banDurs  []time.Duration
	unban    []netip.Addr
	blockset int
}

func (f *fakeEnforcer) Ban(ip netip.Addr, dur time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bans = append(f.bans, ip)
	f.banDurs = append(f.banDurs, dur)
	return nil
}
func (f *fakeEnforcer) Unban(ip netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unban = append(f.unban, ip)
	return nil
}
func (f *fakeEnforcer) ReplaceBlockset(v4, v6 []netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockset = len(v4) + len(v6)
	return nil
}
func (f *fakeEnforcer) EnsureBaselineAccept(*slog.Logger) {}
func (f *fakeEnforcer) Close() error                      { return nil }
func (f *fakeEnforcer) banCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bans)
}

// fakeNotifier counts notifications.
type fakeNotifier struct {
	mu           sync.Mutex
	events       []notify.Event
	healthEvents []notify.HealthEvent
}

func (n *fakeNotifier) Notify(_ context.Context, ev notify.Event) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, ev)
	return nil
}
func (n *fakeNotifier) NotifyHealth(_ context.Context, ev notify.HealthEvent) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.healthEvents = append(n.healthEvents, ev)
	return nil
}
func (n *fakeNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.events)
}

type harness struct {
	app  *App
	enf  *fakeEnforcer
	noti *fakeNotifier
	st   *state.Store
}

func newHarness(t *testing.T, threshold int, dryRun bool) *harness {
	t.Helper()
	p, err := parse.NewLineParser(lineRegex)
	if err != nil {
		t.Fatal(err)
	}
	m, err := detect.NewMatcher([]string{`\.(php|env)(\?|/|$)`, `/(wp-login|xmlrpc)`})
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.Load(filepath.Join(t.TempDir(), "state.json"), time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	enf := &fakeEnforcer{}
	noti := &fakeNotifier{}

	httpDet := &Detector{
		Name:   "http",
		Window: detect.Hits(threshold, time.Minute),
		Inspect: func(line string) (ip, sub, reason string, ok bool) {
			ev, matched := p.Parse(line)
			if !matched || !m.IsBad(ev.URI) {
				return "", "", "", false
			}
			return ev.IP, "", ev.URI, true
		},
	}

	fixed := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	d := Deps{
		Detectors:   []*Detector{httpDet},
		Allow:       allow.New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}),
		State:       st,
		Enforcer:    enf,
		Notifier:    noti,
		BanDuration: time.Hour,
		DryRun:      dryRun,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:         func() time.Time { return fixed },
	}
	return &harness{app: New(d), enf: enf, noti: noti, st: st}
}

func logLine(ip, uri string) string {
	return ip + ` - - [01/Jan/2024:00:00:00 +0000] "GET ` + uri + ` HTTP/1.1" 404 0 "-" "-"`
}

func TestPipeline_BansOnBadURI(t *testing.T) {
	h := newHarness(t, 1, false)
	h.app.ProcessLine(logLine("1.2.3.4", "/wp-login.php"))

	if h.enf.banCount() != 1 {
		t.Fatalf("ban count=%d want 1", h.enf.banCount())
	}
	if h.noti.count() != 1 {
		t.Fatalf("notify count=%d want 1", h.noti.count())
	}
	if !h.st.IsBanned("1.2.3.4", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("state should record ban")
	}
}

func TestPipeline_IgnoresCleanURI(t *testing.T) {
	h := newHarness(t, 1, false)
	h.app.ProcessLine(logLine("1.2.3.4", "/api/users"))
	if h.enf.banCount() != 0 || h.noti.count() != 0 {
		t.Fatal("clean URI must not ban")
	}
}

func TestPipeline_AllowlistedNeverBanned(t *testing.T) {
	h := newHarness(t, 1, false)
	h.app.ProcessLine(logLine("10.1.2.3", "/wp-login.php"))
	if h.enf.banCount() != 0 {
		t.Fatal("allowlisted IP must not be banned")
	}
}

func TestPipeline_ThresholdRequiresRepeats(t *testing.T) {
	h := newHarness(t, 3, false)
	h.app.ProcessLine(logLine("8.8.8.8", "/a.php"))
	h.app.ProcessLine(logLine("8.8.8.8", "/b.php"))
	if h.enf.banCount() != 0 {
		t.Fatal("should not ban before threshold")
	}
	h.app.ProcessLine(logLine("8.8.8.8", "/c.php"))
	if h.enf.banCount() != 1 {
		t.Fatalf("should ban on 3rd hit, got %d", h.enf.banCount())
	}
}

func TestPipeline_NoRenotifyWhenBanned(t *testing.T) {
	h := newHarness(t, 1, false)
	h.app.ProcessLine(logLine("9.9.9.9", "/wp-login.php"))
	h.app.ProcessLine(logLine("9.9.9.9", "/xmlrpc.php")) // already banned
	if h.noti.count() != 1 {
		t.Fatalf("notify count=%d want 1 (no re-notify)", h.noti.count())
	}
	if h.enf.banCount() != 1 {
		t.Fatalf("ban count=%d want 1 (no re-ban)", h.enf.banCount())
	}
	got, _ := h.st.Get("9.9.9.9")
	if got.Hits != 2 {
		t.Fatalf("hits=%d want 2 (second hit counted)", got.Hits)
	}
}

func TestPipeline_DryRunDetectsButDoesNotEnforce(t *testing.T) {
	h := newHarness(t, 1, true)
	h.app.ProcessLine(logLine("1.2.3.4", "/wp-login.php"))

	if h.enf.banCount() != 0 {
		t.Fatal("dry-run must NOT touch the enforcer")
	}
	if h.noti.count() != 1 {
		t.Fatal("dry-run should still notify")
	}
	if h.noti.events[0].DryRun != true {
		t.Fatal("notify event should carry DryRun=true")
	}
}

func TestRestore_LoadsActiveBansIntoEnforcer(t *testing.T) {
	h := newHarness(t, 1, false)
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	h.st.Ban("203.0.113.5", "http", "/x.php", 1, now, now.Add(time.Hour))

	h.app.Restore(context.Background())
	if h.enf.banCount() != 1 {
		t.Fatalf("restore ban count=%d want 1", h.enf.banCount())
	}
}

func TestRestore_DryRunSkipsEnforcer(t *testing.T) {
	h := newHarness(t, 1, true)
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	h.st.Ban("203.0.113.5", "http", "/x.php", 1, now, now.Add(time.Hour))

	h.app.Restore(context.Background())
	if h.enf.banCount() != 0 {
		t.Fatal("dry-run restore must skip enforcer")
	}
}

func TestPipeline_UnparsableLineIgnored(t *testing.T) {
	h := newHarness(t, 1, false)
	h.app.ProcessLine("total garbage")
	h.app.ProcessLine(logLine("not-an-ip", "/wp-login.php"))
	if h.enf.banCount() != 0 {
		t.Fatal("unparsable lines must not ban")
	}
}
