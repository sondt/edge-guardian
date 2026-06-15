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

func TestCoalesce(t *testing.T) {
	mk := func(ss ...string) []netip.Prefix {
		out := make([]netip.Prefix, len(ss))
		for i, s := range ss {
			out[i] = netip.MustParsePrefix(s)
		}
		sortPrefixes(out)
		return out
	}
	tests := []struct {
		name     string
		in, want []netip.Prefix
	}{
		{
			// /24 nested in /16, /32 nested in /24 → only the broadest survives.
			name: "drops nested",
			in:   mk("1.2.3.4/32", "1.2.3.0/24", "1.2.0.0/16"),
			want: mk("1.2.0.0/16"),
		},
		{
			name: "keeps disjoint",
			in:   mk("1.2.0.0/16", "9.9.9.0/24", "45.13.0.0/16"),
			want: mk("1.2.0.0/16", "9.9.9.0/24", "45.13.0.0/16"),
		},
		{
			// FireHOL-style overlap: aggregate /16 already covers a Spamhaus /24.
			name: "mixed overlap and disjoint",
			in:   mk("1.2.0.0/16", "1.2.5.0/24", "8.8.8.0/24"),
			want: mk("1.2.0.0/16", "8.8.8.0/24"),
		},
		{name: "empty", in: nil, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := coalesce(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("coalesce len=%d want %d: %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("coalesce[%d]=%v want %v (full: %v)", i, got[i], tt.want[i], got)
				}
			}
		})
	}
}

func TestIsBogon(t *testing.T) {
	bogon := []string{
		"127.0.0.0/8", "127.0.0.1/32", "10.0.0.0/8", "10.5.6.0/24",
		"192.168.1.0/24", "172.16.0.0/12", "100.64.0.0/10", "169.254.0.0/16",
		"0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
		"::1/128", "fe80::/10", "fc00::/7",
	}
	for _, s := range bogon {
		if !isBogon(netip.MustParsePrefix(s)) {
			t.Errorf("isBogon(%s) = false, want true", s)
		}
	}
	routable := []string{"1.2.3.0/24", "9.9.9.9/32", "185.220.101.0/24", "45.13.0.0/16", "8.8.8.0/24", "2606:4700::/32"}
	for _, s := range routable {
		if isBogon(netip.MustParsePrefix(s)) {
			t.Errorf("isBogon(%s) = true, want false", s)
		}
	}
}

func TestFetchAll_StripsBogons(t *testing.T) {
	// A source full of non-routable ranges (as FireHOL level1 actually contains) must
	// load NOTHING into the drop set — otherwise the host blackholes its own loopback.
	body := "127.0.0.0/8\n10.0.0.0/8\n192.168.0.0/16\n169.254.0.0/16\n100.64.0.0/10\n1.2.3.0/24\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	set, errs := FetchAll(context.Background(), http.DefaultClient, []string{srv.URL}, nil)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(set.V4) != 1 || set.V4[0].String() != "1.2.3.0/24" {
		t.Fatalf("bogons not stripped, v4=%v want [1.2.3.0/24]", set.V4)
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
