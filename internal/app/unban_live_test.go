package app

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestUnbanLive_RemovesEverywhere(t *testing.T) {
	h := newHarness(t, 1, false)
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Ban first.
	h.app.ProcessLine(logLine("203.0.113.7", "/wp-login.php"))
	if !h.st.IsBanned("203.0.113.7", now) {
		t.Fatal("precondition: should be banned")
	}

	if err := h.app.UnbanLive(context.Background(), "203.0.113.7"); err != nil {
		t.Fatalf("UnbanLive: %v", err)
	}

	if h.st.IsBanned("203.0.113.7", now) {
		t.Fatal("state should no longer be banned")
	}
	wantUnban := netip.MustParseAddr("203.0.113.7")
	if len(h.enf.unban) != 1 || h.enf.unban[0] != wantUnban {
		t.Fatalf("enforcer.unban=%v want [%v]", h.enf.unban, wantUnban)
	}
}

func TestUnbanLive_DryRunSkipsEnforcer(t *testing.T) {
	h := newHarness(t, 1, true)
	h.app.ProcessLine(logLine("203.0.113.8", "/wp-login.php"))

	if err := h.app.UnbanLive(context.Background(), "203.0.113.8"); err != nil {
		t.Fatalf("UnbanLive: %v", err)
	}
	if len(h.enf.unban) != 0 {
		t.Fatal("dry-run UnbanLive must not call the enforcer")
	}
}

func TestUnbanLive_InvalidIP(t *testing.T) {
	h := newHarness(t, 1, false)
	if err := h.app.UnbanLive(context.Background(), "nope"); err == nil {
		t.Fatal("expected error for invalid ip")
	}
}

func TestUnbanLive_NormalizesMappedIPv6(t *testing.T) {
	h := newHarness(t, 1, false)
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// Ban an IPv4-mapped IPv6 address as the log might present it.
	h.app.ProcessLine(logLine("::ffff:203.0.113.9", "/wp-login.php"))

	// Stored under canonical "203.0.113.9".
	if !h.st.IsBanned("203.0.113.9", now) {
		t.Fatal("ban should be keyed on canonical IPv4 form")
	}
	// Unban using the mapped form must still find and remove it.
	if err := h.app.UnbanLive(context.Background(), "::ffff:203.0.113.9"); err != nil {
		t.Fatalf("UnbanLive: %v", err)
	}
	if h.st.IsBanned("203.0.113.9", now) {
		t.Fatal("mapped-form unban should clear the canonical entry")
	}
}
