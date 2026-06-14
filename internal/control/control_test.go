package control

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeUnbanner records the IPs requested for unban.
type fakeUnbanner struct {
	mu      sync.Mutex
	ips     []string
	failMsg string
}

func (f *fakeUnbanner) UnbanLive(_ context.Context, ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failMsg != "" {
		return &unbanErr{f.failMsg}
	}
	f.ips = append(f.ips, ip)
	return nil
}
func (f *fakeUnbanner) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ips...)
}

type unbanErr struct{ msg string }

func (e *unbanErr) Error() string { return e.msg }

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// shortSocket returns a short socket path under /tmp to stay within the
// ~104-char unix socket path limit on macOS.
func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "nsg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

func startServer(t *testing.T, unb Unbanner) string {
	t.Helper()
	path := shortSocket(t)
	srv := NewServer(path, unb, discardLog())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() { _ = srv.Start(ctx) }()

	// Wait for the socket to appear.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("control socket did not come up")
	return ""
}

func TestSendUnban_RoundTrip(t *testing.T) {
	unb := &fakeUnbanner{}
	path := startServer(t, unb)

	if err := SendUnban(path, "1.2.3.4"); err != nil {
		t.Fatalf("SendUnban: %v", err)
	}
	got := unb.got()
	if len(got) != 1 || got[0] != "1.2.3.4" {
		t.Fatalf("unbanned=%v want [1.2.3.4]", got)
	}
}

func TestSendUnban_DaemonError(t *testing.T) {
	unb := &fakeUnbanner{failMsg: "nftables: boom"}
	path := startServer(t, unb)

	err := SendUnban(path, "9.9.9.9")
	if err == nil {
		t.Fatal("expected error from daemon")
	}
	if got := unb.got(); len(got) != 0 {
		t.Fatalf("should not record on failure, got %v", got)
	}
}

func TestSendUnban_DaemonNotRunning(t *testing.T) {
	// Short path under /tmp (the dir exists, the socket file does not) so dialing
	// yields ENOENT rather than EINVAL from an over-long macOS socket path.
	path := shortSocket(t) // returns <shortdir>/c.sock, not created
	err := SendUnban(path, "1.2.3.4")
	if err != ErrDaemonNotRunning {
		t.Fatalf("err=%v want ErrDaemonNotRunning", err)
	}
}

func TestSendUnban_StaleSocketNoListener(t *testing.T) {
	// A socket file exists but nothing listens => ECONNREFUSED => daemon not running.
	path := shortSocket(t)
	srv := NewServer(path, &fakeUnbanner{}, discardLog())
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Start(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	// Give Start a moment to stop listening; the socket file may linger briefly.
	time.Sleep(50 * time.Millisecond)
	if err := SendUnban(path, "1.2.3.4"); err != ErrDaemonNotRunning {
		// If the file was already unlinked it's ENOENT, still ErrDaemonNotRunning.
		t.Fatalf("err=%v want ErrDaemonNotRunning", err)
	}
}

func TestServer_Ping(t *testing.T) {
	path := startServer(t, &fakeUnbanner{})
	if err := send(path, Request{Cmd: "ping"}); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestServer_UnknownCommand(t *testing.T) {
	path := startServer(t, &fakeUnbanner{})
	if err := send(path, Request{Cmd: "frobnicate"}); err == nil {
		t.Fatal("expected error for unknown command")
	}
}

func TestServer_UnbanMissingIP(t *testing.T) {
	path := startServer(t, &fakeUnbanner{})
	if err := send(path, Request{Cmd: "unban"}); err == nil {
		t.Fatal("expected error when ip missing")
	}
}

func TestServer_SocketPermissions(t *testing.T) {
	path := startServer(t, &fakeUnbanner{})
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket perm=%o want 600", perm)
	}
}

func TestServer_RemovesStaleSocket(t *testing.T) {
	path := shortSocket(t)
	// Pre-create a stale file at the socket path.
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(path, &fakeUnbanner{}, discardLog())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Start(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := SendUnban(path, "5.5.5.5"); err == nil {
			return // listening over the replaced socket
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not replace stale socket")
}
