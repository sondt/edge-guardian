package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_Version(t *testing.T) {
	if err := run([]string{"--version"}); err != nil {
		t.Fatalf("--version: %v", err)
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	err := run([]string{"frobnicate"})
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("expected unknown command error, got %v", err)
	}
}

func TestRun_UnbanMissingIP(t *testing.T) {
	err := run([]string{"unban"})
	if err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("expected usage error, got %v", err)
	}
}

func TestRun_UnbanMissingConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.toml")
	err := run([]string{"--config", missing, "unban", "1.2.3.4"})
	if err == nil {
		t.Fatal("expected error loading missing config")
	}
}

func TestRun_DaemonMissingConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.toml")
	if err := run([]string{"-c", missing}); err == nil {
		t.Fatal("expected error loading missing config for daemon")
	}
}

func TestRun_BadFlag(t *testing.T) {
	if err := run([]string{"--nope"}); err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestNewLogger_Levels(t *testing.T) {
	for _, lvl := range []string{"debug", "info", "warn", "error", ""} {
		t.Setenv("LOG_LEVEL", lvl)
		if newLogger() == nil {
			t.Fatalf("nil logger for level %q", lvl)
		}
	}
}

func TestRun_UnbanInvalidIP(t *testing.T) {
	// Valid config but an invalid IP: should fail before touching the enforcer.
	cfg := `
[log]
paths = ["/var/log/nginx/access.log"]
[detection]
bad_uri_patterns = ['\.php(\?|/|$)']
threshold = 1
window_secs = 60
[ban]
duration = "168h"
whitelist = ["127.0.0.0/8"]
nft_table = "edge_guardian"
nft_set_v4 = "blocklist4"
nft_set_v6 = "blocklist6"
[telegram]
enabled = false
[state]
path = "` + filepath.Join(t.TempDir(), "state.json") + `"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config", path, "unban", "not-an-ip"}); err == nil {
		t.Fatal("expected invalid ip error")
	}
}
