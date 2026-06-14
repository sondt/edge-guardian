package allow

import (
	"net/netip"
	"testing"
)

func mustPrefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("parse prefix %q: %v", s, err)
		}
		out = append(out, p)
	}
	return out
}

func TestList_Contains(t *testing.T) {
	l := New(mustPrefixes(t, "127.0.0.0/8", "10.106.49.0/24", "::1/128", "2001:db8::/32"))

	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.106.49.7", true},
		{"10.106.50.1", false},
		{"8.8.8.8", false},
		{"::1", true},
		{"2001:db8::dead", true},
		{"2001:dead::1", false},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.ip)
			if got := l.Contains(addr); got != tt.want {
				t.Fatalf("Contains(%s)=%v want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestList_ContainsString(t *testing.T) {
	l := New(mustPrefixes(t, "10.0.0.0/8"))

	if allowed, valid := l.ContainsString("10.1.2.3"); !allowed || !valid {
		t.Fatalf("allowed=%v valid=%v want true,true", allowed, valid)
	}
	if allowed, valid := l.ContainsString("not-an-ip"); allowed || valid {
		t.Fatalf("allowed=%v valid=%v want false,false", allowed, valid)
	}
}

func TestList_InvalidAddr(t *testing.T) {
	l := New(mustPrefixes(t, "10.0.0.0/8"))
	if l.Contains(netip.Addr{}) {
		t.Fatal("invalid addr must not be allowlisted")
	}
}

func TestList_IsolatedFromCallerSlice(t *testing.T) {
	prefixes := mustPrefixes(t, "10.0.0.0/8")
	l := New(prefixes)
	prefixes[0] = netip.MustParsePrefix("192.168.0.0/16") // mutate caller's slice
	if !l.Contains(netip.MustParseAddr("10.1.1.1")) {
		t.Fatal("List should copy prefixes, not alias caller's slice")
	}
}
