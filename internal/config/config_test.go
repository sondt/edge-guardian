package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const validTOML = `
[log]
paths = ["/var/log/nginx/access.log"]

[detection]
bad_uri_patterns = ['\.(php|env)(\?|/|$)']
threshold = 1
window_secs = 60

[ban]
duration = "168h"
whitelist = ["127.0.0.0/8", "10.0.0.0/8"]
nft_table = "edge_guardian"
nft_set_v4 = "blocklist4"
nft_set_v6 = "blocklist6"

[telegram]
enabled = false

[state]
path = "/var/lib/edge-guardian/state.json"
`

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_Valid(t *testing.T) {
	cfg, err := Load(writeTemp(t, validTOML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Detection.Threshold != 1 {
		t.Fatalf("threshold=%d", cfg.Detection.Threshold)
	}
	d, err := cfg.BanDuration()
	if err != nil || d != 168*time.Hour {
		t.Fatalf("BanDuration=%v err=%v", d, err)
	}
	if cfg.WindowDuration() != 60*time.Second {
		t.Fatalf("window=%v", cfg.WindowDuration())
	}
	wl, err := cfg.Whitelist()
	if err != nil || len(wl) != 2 {
		t.Fatalf("whitelist=%v err=%v", wl, err)
	}
	// Defaults applied for unspecified line_regex.
	if cfg.Log.LineRegex == "" {
		t.Fatal("line_regex default not applied")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.toml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidate_Errors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no paths", func(c *Config) { c.Log.Paths = nil }},
		{"bad line_regex no groups", func(c *Config) { c.Log.LineRegex = `^\S+` }},
		{"empty patterns", func(c *Config) { c.Detection.BadURIPatterns = nil }},
		{"bad pattern", func(c *Config) { c.Detection.BadURIPatterns = []string{"("} }},
		{"threshold zero", func(c *Config) { c.Detection.Threshold = 0 }},
		{"window zero", func(c *Config) { c.Detection.WindowSecs = 0 }},
		{"bad duration", func(c *Config) { c.Ban.Duration = "nope" }},
		{"bad whitelist", func(c *Config) { c.Ban.Whitelist = []string{"not-a-cidr"} }},
		{"empty nft", func(c *Config) { c.Ban.NftTable = "" }},
		{"telegram missing token", func(c *Config) {
			c.Telegram.Enabled = true
			c.Telegram.ChatID = "x"
		}},
		{"empty state path", func(c *Config) { c.State.Path = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected validation error for %s", tt.name)
			}
		})
	}
}

func TestValidate_SSHD(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"disabled ignores fields", func(c *Config) { c.SSHD = SSHDConfig{Enabled: false} }, false},
		{"enabled valid", func(c *Config) {
			c.SSHD = SSHDConfig{Enabled: true, Paths: []string{"/var/log/auth.log"}, Threshold: 5, WindowSecs: 60}
		}, false},
		{"enabled no paths", func(c *Config) {
			c.SSHD = SSHDConfig{Enabled: true, Threshold: 5, WindowSecs: 60}
		}, true},
		{"enabled threshold zero", func(c *Config) {
			c.SSHD = SSHDConfig{Enabled: true, Paths: []string{"/var/log/auth.log"}, Threshold: 0, WindowSecs: 60}
		}, true},
		{"enabled window zero", func(c *Config) {
			c.SSHD = SSHDConfig{Enabled: true, Paths: []string{"/var/log/auth.log"}, Threshold: 5, WindowSecs: 0}
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			if err := cfg.Validate(); (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestParseDuration_Days(t *testing.T) {
	d, err := parseDuration("7d")
	if err != nil || d != 7*24*time.Hour {
		t.Fatalf("7d => %v err=%v", d, err)
	}
	if _, err := parseDuration("0d"); err == nil {
		t.Fatal("0d should error")
	}
	if _, err := parseDuration("-5h"); err == nil {
		t.Fatal("negative should error")
	}
}

func validConfig() Config {
	c := Defaults()
	c.Log.Paths = []string{"/var/log/nginx/access.log"}
	return c
}
