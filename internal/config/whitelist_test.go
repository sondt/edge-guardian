package config

import (
	"net/netip"
	"testing"
)

func TestWhitelist_AcceptsCIDRAndBareIP(t *testing.T) {
	c := Config{Ban: BanConfig{Whitelist: []string{
		"10.0.0.0/8",    // CIDR v4
		"203.0.113.7",   // bare IPv4 → /32
		"2001:db8::1",   // bare IPv6 → /128
		"::1",           // bare loopback v6 → /128
		" 192.168.1.5 ", // surrounding spaces tolerated
	}}}
	wl, err := c.Whitelist()
	if err != nil {
		t.Fatalf("Whitelist() err = %v", err)
	}
	if len(wl) != 5 {
		t.Fatalf("got %d prefixes, want 5", len(wl))
	}
	// Bare IPv4 must become a /32 that contains exactly that address.
	want := netip.MustParseAddr("203.0.113.7")
	var got netip.Prefix
	for _, p := range wl {
		if p.Bits() == 32 && p.Contains(want) {
			got = p
		}
	}
	if !got.IsValid() || got.Bits() != 32 {
		t.Fatalf("bare IPv4 did not become a /32: %v", wl)
	}
	// And it must NOT contain a different host.
	if got.Contains(netip.MustParseAddr("203.0.113.8")) {
		t.Fatal("/32 should only match its own address")
	}
	// Bare IPv6 → /128.
	for _, p := range wl {
		if p.Addr().Is6() && p.Addr() == netip.MustParseAddr("2001:db8::1") && p.Bits() != 128 {
			t.Fatalf("bare IPv6 should be /128, got /%d", p.Bits())
		}
	}
}

func TestWhitelist_RejectsGarbage(t *testing.T) {
	c := Config{Ban: BanConfig{Whitelist: []string{"not-an-ip"}}}
	if _, err := c.Whitelist(); err == nil {
		t.Fatal("expected error for garbage whitelist entry")
	}
}
