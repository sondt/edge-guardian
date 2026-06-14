package geoip

import (
	"reflect"
	"testing"
)

func TestNilResolverIsNoOp(t *testing.T) {
	var r *Resolver
	if got := r.Lookup("8.8.8.8"); got != (Result{}) {
		t.Fatalf("nil resolver should return empty Result, got %+v", got)
	}
	c, a := r.Stats()
	if c != 0 || a != 0 {
		t.Fatalf("nil Stats=%d,%d want 0,0", c, a)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
}

func TestNop(t *testing.T) {
	if got := (Nop{}).Lookup("1.2.3.4"); got != (Result{}) {
		t.Fatalf("Nop should be empty, got %+v", got)
	}
}

func TestEmptyPathsNoOp(t *testing.T) {
	r, err := New("", "")
	if err != nil {
		t.Fatalf("New(\"\",\"\"): %v", err)
	}
	defer r.Close()
	if c, a := r.Stats(); c != 0 || a != 0 {
		t.Fatalf("empty Stats=%d,%d want 0,0", c, a)
	}
	if got := r.Lookup("1.1.1.1"); got != (Result{}) {
		t.Fatalf("no DB should return empty, got %+v", got)
	}
}

func TestMissingFileReturnsError(t *testing.T) {
	if _, err := New("/no/such/city.mmdb", ""); err == nil {
		t.Fatal("expected error for missing City DB")
	}
	if _, err := New("", "/no/such/asn.mmdb"); err == nil {
		t.Fatal("expected error for missing ASN DB")
	}
}

func TestMissingFileInListReturnsError(t *testing.T) {
	if _, err := New("/no/v4.mmdb,/no/v6.mmdb", ""); err == nil {
		t.Fatal("expected error when a listed file is missing")
	}
}

func TestSplitPaths(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a.mmdb", []string{"a.mmdb"}},
		{"a.mmdb,b.mmdb", []string{"a.mmdb", "b.mmdb"}},
		{" a.mmdb , , b.mmdb ", []string{"a.mmdb", "b.mmdb"}},
		{",,", nil},
	}
	for _, tt := range tests {
		if got := splitPaths(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("splitPaths(%q)=%v want %v", tt.in, got, tt.want)
		}
	}
}

func TestInternalIPDetection(t *testing.T) {
	r, _ := New("", "")
	for _, ip := range []string{"10.1.2.3", "192.168.1.1", "172.16.0.1", "127.0.0.1", "::1", "169.254.1.1", "fe80::1"} {
		if got := r.Lookup(ip); !got.IsInternal {
			t.Fatalf("Lookup(%s) should be IsInternal", ip)
		}
	}
}

func TestPublicIPNotInternal(t *testing.T) {
	r, _ := New("", "")
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "185.220.101.5", "2001:db8::1"} {
		if got := r.Lookup(ip); got.IsInternal {
			t.Fatalf("Lookup(%s) should NOT be internal", ip)
		}
	}
}

func TestGarbageIP(t *testing.T) {
	r, _ := New("", "")
	if got := r.Lookup("not-an-ip"); got != (Result{}) {
		t.Fatalf("garbage IP should return empty, got %+v", got)
	}
}

func TestResultASNLabel(t *testing.T) {
	tests := []struct {
		r    Result
		want string
	}{
		{Result{ASN: 24940, Org: "Hetzner"}, "AS24940 Hetzner"},
		{Result{ASN: 24940}, "AS24940"},
		{Result{Org: "Hetzner"}, "Hetzner"},
		{Result{}, ""},
	}
	for _, tt := range tests {
		if got := tt.r.ASNLabel(); got != tt.want {
			t.Fatalf("ASNLabel(%+v)=%q want %q", tt.r, got, tt.want)
		}
	}
}

func TestLooksLikeHosting(t *testing.T) {
	for _, org := range []string{"DigitalOcean LLC", "Hetzner Online GmbH", "Amazon AWS", "Some VPS Hosting"} {
		if !looksLikeHosting(org) {
			t.Fatalf("%q should look like hosting", org)
		}
	}
	for _, org := range []string{"Viettel Group", "Comcast Cable", ""} {
		if looksLikeHosting(org) {
			t.Fatalf("%q should NOT look like hosting", org)
		}
	}
}
