package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

const fireholSample = `# FireHOL level1 sample
# comment line
1.2.3.0/24
9.9.9.9
10.0.0.0/8

# blank line above
185.220.101.0/24
`

const spamhausSample = `; Spamhaus DROP sample
; another comment
45.13.0.0/16 ; SBL123
2001:db8::/32 ; SBL456
`

func TestParse_FireHOL(t *testing.T) {
	got := Parse(strings.NewReader(fireholSample))
	want := map[string]bool{"1.2.3.0/24": true, "9.9.9.9/32": true, "10.0.0.0/8": true, "185.220.101.0/24": true}
	if len(got) != len(want) {
		t.Fatalf("parsed %d prefixes want %d: %v", len(got), len(want), got)
	}
	for _, p := range got {
		if !want[p.String()] {
			t.Fatalf("unexpected prefix %s", p)
		}
	}
}

func TestParse_Spamhaus(t *testing.T) {
	got := Parse(strings.NewReader(spamhausSample))
	if len(got) != 2 {
		t.Fatalf("parsed %d want 2: %v", len(got), got)
	}
	if got[0].String() != "45.13.0.0/16" {
		t.Fatalf("got %s want 45.13.0.0/16", got[0])
	}
}

func TestParseLine(t *testing.T) {
	tests := []struct {
		line string
		want string // "" = should not parse
	}{
		{"1.2.3.0/24", "1.2.3.0/24"},
		{"9.9.9.9", "9.9.9.9/32"},
		{"  1.2.3.4  ", "1.2.3.4/32"},
		{"45.13.0.0/16 ; SBL123", "45.13.0.0/16"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"# comment", ""},
		{"; comment", ""},
		{"", ""},
		{"not-an-ip", ""},
		{"1.2.3.5/24", "1.2.3.0/24"}, // masked to network
	}
	for _, tt := range tests {
		p, ok := parseLine(tt.line)
		if tt.want == "" {
			if ok {
				t.Fatalf("parseLine(%q) should fail, got %s", tt.line, p)
			}
			continue
		}
		if !ok || p.String() != tt.want {
			t.Fatalf("parseLine(%q)=%s,%v want %s", tt.line, p, ok, tt.want)
		}
	}
}

type fakeAllow struct{ prefixes []netip.Prefix }

func (f fakeAllow) Contains(a netip.Addr) bool {
	for _, p := range f.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func TestFetchAll(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fireholSample))
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(spamhausSample))
	}))
	defer srv2.Close()

	// Allowlist 10.0.0.0/8 → that FireHOL entry must be excluded.
	allow := fakeAllow{prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	set, errs := FetchAll(context.Background(), http.DefaultClient, []string{srv1.URL, srv2.URL}, allow)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	// v4: 1.2.3.0/24, 9.9.9.9/32, 185.220.101.0/24, 45.13.0.0/16 (10.0.0.0/8 excluded) = 4
	if len(set.V4) != 4 {
		t.Fatalf("v4=%d want 4: %v", len(set.V4), set.V4)
	}
	if len(set.V6) != 1 {
		t.Fatalf("v6=%d want 1: %v", len(set.V6), set.V6)
	}
	for _, p := range set.V4 {
		if p.String() == "10.0.0.0/8" {
			t.Fatal("allowlisted range must be excluded")
		}
	}
}

func TestFetchAll_BadSourceSkipped(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1.2.3.0/24\n"))
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	set, errs := FetchAll(context.Background(), http.DefaultClient, []string{bad.URL, good.URL}, nil)
	if len(errs) != 1 {
		t.Fatalf("want 1 error from bad source, got %d", len(errs))
	}
	if len(set.V4) != 1 {
		t.Fatalf("good source should still load, v4=%d", len(set.V4))
	}
}
