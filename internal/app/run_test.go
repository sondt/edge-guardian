package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sondt/edge-guardian/internal/config"
	"github.com/sondt/edge-guardian/internal/ingest"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestRun_EndToEnd tails a real temp log file and verifies a bad line triggers a ban.
func TestRun_EndToEnd(t *testing.T) {
	h := newHarness(t, 1, false)
	// Use real wall-clock time so the sliding window matches freshly-written lines.
	h.app.now = time.Now

	logPath := writeFile(t, "")
	tailer := ingest.New([]string{logPath})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = h.app.Run(ctx, tailer)
		close(done)
	}()

	// Give the tailer a moment to start following, then append a scanner hit.
	time.Sleep(200 * time.Millisecond)
	appendLine(t, logPath, logLine("198.51.100.7", "/wp-login.php"))

	waitFor(t, 3*time.Second, func() bool { return h.enf.banCount() == 1 })

	cancel()
	<-done

	if h.noti.count() != 1 {
		t.Fatalf("notify count=%d want 1", h.noti.count())
	}
}

// TestBuild_FromConfig exercises the assembly path (Build + Cleanup).
func TestBuild_FromConfig(t *testing.T) {
	statePath := writeFile(t, "")
	cfg := config.Defaults()
	cfg.Log.Paths = []string{writeFile(t, "")}
	cfg.State.Path = statePath
	cfg.Telegram.Enabled = false
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	comps, err := Build(cfg, discardLogger())
	if err != nil {
		// On Linux the real nftables enforcer is used; without an initialized edge_guardian
		// table / netlink privileges (e.g. CI), enforcer init fails. That's not what
		// this assembly test checks — skip rather than fail.
		if strings.Contains(err.Error(), "enforcer") || strings.Contains(err.Error(), "nftables") || strings.Contains(err.Error(), "netlink") {
			t.Skipf("Build needs an initialized nftables table (skipping): %v", err)
		}
		t.Fatalf("Build: %v", err)
	}
	if comps.App == nil {
		t.Fatal("nil app")
	}
	comps.Cleanup() // should not panic and should save state
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state file not written: %v", err)
	}
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ns-*.log")
	if err != nil {
		t.Fatal(err)
	}
	if content != "" {
		_, _ = f.WriteString(content)
	}
	name := f.Name()
	_ = f.Close()
	return name
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
