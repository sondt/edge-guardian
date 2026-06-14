// Package geoip resolves source IPs (of attackers) into location info (country/region/
// city) and network info (ASN/ISP) FULLY OFFLINE from MMDB files (MaxMind format), to
// enrich ban notifications and the dashboard. It does NOT call external geolocation APIs.
//
// Recommended data source: the free CC-licensed City + ASN MMDB sets from
// "sapics/ip-location-db" (MaxMind-format compatible). The sapics City set is ONLY
// published as separate IPv4 and IPv6 files (no combined file), so each path parameter
// accepts a comma-separated LIST of files — for example pointing to both
// "dbip-city-ipv4.mmdb,dbip-city-ipv6.mmdb" to cover both address families. Lookup queries
// each reader in turn until a file contains that IP.
//
// The Resolver always degrades SAFELY: missing file / empty path / corrupt file → no-op
// returning an empty Result. Lookup NEVER returns an error and is nil-safe.
package geoip

import (
	"fmt"
	"net"
	"strings"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// TECHNICAL NOTE: we use maxminddb-golang to READ DIRECTLY instead of geoip2-golang. Reason:
// sapics/ip-location-db mmdb files set a non-standard `database_type` metadata ("city ipv4",
// "asn ipv4") which makes geoip2-golang block at the .City()/.ASN() methods ("reader does not
// support the X database type") EVEN THOUGH the data inside still follows the MaxMind schema.
// Reading directly via maxminddb.Lookup into a MaxMind-schema struct bypasses that guard → it
// works with BOTH sapics files AND standard MaxMind/DB-IP files.

// mmCity is the NESTED MaxMind/DB-IP schema portion to extract from the City DB.
type mmCity struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
	Traits struct {
		IsAnonymousProxy bool `maxminddb:"is_anonymous_proxy"`
		IsAnycast        bool `maxminddb:"is_anycast"`
	} `maxminddb:"traits"`
}

// mmCityFlat is the FLAT schema of sapics/ip-location-db dbip-city (country_code/city/
// state1/…). Completely different from MaxMind's NESTED schema — sapics files use this one.
type mmCityFlat struct {
	CountryCode string  `maxminddb:"country_code"` // ISO code (e.g. "VN","US")
	City        string  `maxminddb:"city"`
	State1      string  `maxminddb:"state1"` // province/state
	State2      string  `maxminddb:"state2"` // district/county (if any)
	Latitude    float64 `maxminddb:"latitude"`
	Longitude   float64 `maxminddb:"longitude"`
}

// mmASN is the schema portion to extract from the ASN DB.
type mmASN struct {
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

// Result is the info resolved for an IP. An empty field = unknown.
// IsInternal=true for internal IPs (private/loopback/link-local) — not looked up in the DB.
type Result struct {
	Country    string  // country name (preferred) or ISO code. E.g. "Vietnam" / "VN".
	Region     string  // province/region (subdivision).
	City       string  // city/district.
	Lat        float64 // approximate city-level latitude.
	Lon        float64 // approximate city-level longitude.
	ASN        int     // autonomous system number. 0 = unknown.
	Org        string  // ISP/organization name. E.g. "Viettel Group".
	IsHosting  bool    // datacenter/hosting/VPN flag (best-effort) — attackers often come from here.
	IsInternal bool    // internal IP (private/loopback/link-local).
}

// ASNLabel formats ASN + organization into a short label: "AS24940 Hetzner" / "AS24940" /
// "Hetzner" / "" (unknown).
func (r Result) ASNLabel() string {
	switch {
	case r.ASN != 0 && r.Org != "":
		return fmt.Sprintf("AS%d %s", r.ASN, r.Org)
	case r.ASN != 0:
		return fmt.Sprintf("AS%d", r.ASN)
	default:
		return r.Org
	}
}

// Nop is a no-op resolver (every Lookup returns an empty Result). Used when GeoIP is disabled.
type Nop struct{}

// Lookup on Nop always returns an empty Result.
func (Nop) Lookup(string) Result { return Result{} }

// Resolver looks up location + network for an IP. A nil pointer = no-op (safe when not yet wired).
// Each kind keeps a LIST of readers (to cover separate IPv4 + IPv6 files).
type Resolver struct {
	city []*maxminddb.Reader
	asn  []*maxminddb.Reader
}

// splitPaths splits a comma-separated path string into a trimmed list, dropping empty elements.
func splitPaths(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// New opens the MMDB readers. Each parameter is a comma-separated LIST of files
// (to cover separate IPv4 + IPv6); empty → skip the corresponding kind. A missing/unreadable
// file → returns an error BUT keeps the already-opened readers (the caller should log a
// warning and continue). Returns a *Resolver that is always non-nil even when all paths are
// empty (pure no-op).
func New(cityDBPaths, asnDBPaths string) (*Resolver, error) {
	r := &Resolver{}
	for _, p := range splitPaths(cityDBPaths) {
		reader, err := maxminddb.Open(p)
		if err != nil {
			return r, fmt.Errorf("open GeoIP City DB %q: %w", p, err)
		}
		r.city = append(r.city, reader)
	}
	for _, p := range splitPaths(asnDBPaths) {
		reader, err := maxminddb.Open(p)
		if err != nil {
			return r, fmt.Errorf("open GeoIP ASN DB %q: %w", p, err)
		}
		r.asn = append(r.asn, reader)
	}
	return r, nil
}

// Stats returns the number of successfully opened City/ASN readers — for diagnostic logging at startup. nil-safe.
func (r *Resolver) Stats() (city, asn int) {
	if r == nil {
		return 0, 0
	}
	return len(r.city), len(r.asn)
}

// Close closes every open reader. nil-safe. Returns an error to match the io.Closer-style interface.
func (r *Resolver) Close() error {
	if r == nil {
		return nil
	}
	for _, rd := range r.city {
		_ = rd.Close()
	}
	for _, rd := range r.asn {
		_ = rd.Close()
	}
	return nil
}

// Lookup resolves an IP (string) into a Result. NEVER returns an error: a garbage IP → empty
// Result; an internal IP → IsInternal=true (not looked up in the DB); a missing reader → the
// corresponding part is left empty. nil-safe.
func (r *Resolver) Lookup(ipStr string) Result {
	if r == nil {
		return Result{}
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Result{}
	}
	if isInternalIP(ip) {
		return Result{IsInternal: true}
	}
	var res Result
	r.fillCity(ip, &res)
	r.fillASN(ip, &res)
	return res
}

func (r *Resolver) fillCity(ip net.IP, res *Result) {
	for _, rd := range r.city {
		if applyCity(rd, ip, res) {
			return
		}
	}
}

// applyCity tries to decode one reader against BOTH schemas: the FLAT sapics one first, then
// the NESTED MaxMind one. Returns true if a country was obtained.
func applyCity(rd *maxminddb.Reader, ip net.IP, res *Result) bool {
	var f mmCityFlat
	if err := rd.Lookup(ip, &f); err == nil && f.CountryCode != "" {
		res.Country = f.CountryCode
		res.Region = firstNonEmpty(f.State1, f.State2)
		res.City = f.City
		res.Lat = f.Latitude
		res.Lon = f.Longitude
		return true
	}
	var n mmCity
	if err := rd.Lookup(ip, &n); err == nil {
		country := pickName(n.Country.Names, n.Country.ISOCode)
		if country == "" {
			return false
		}
		res.Country = country
		if len(n.Subdivisions) > 0 {
			res.Region = pickName(n.Subdivisions[0].Names, n.Subdivisions[0].ISOCode)
		}
		res.City = pickName(n.City.Names, "")
		res.Lat = n.Location.Latitude
		res.Lon = n.Location.Longitude
		if n.Traits.IsAnonymousProxy || n.Traits.IsAnycast {
			res.IsHosting = true
		}
		return true
	}
	return false
}

func (r *Resolver) fillASN(ip net.IP, res *Result) {
	for _, rd := range r.asn {
		var a mmASN
		if err := rd.Lookup(ip, &a); err != nil {
			continue
		}
		if a.AutonomousSystemNumber == 0 && a.AutonomousSystemOrganization == "" {
			continue
		}
		res.ASN = int(a.AutonomousSystemNumber)
		res.Org = a.AutonomousSystemOrganization
		if !res.IsHosting && looksLikeHosting(res.Org) {
			res.IsHosting = true
		}
		return
	}
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// pickName prefers the English name → any name → fallback (ISO code).
func pickName(names map[string]string, fallback string) string {
	if names != nil {
		if v := strings.TrimSpace(names["en"]); v != "" {
			return v
		}
		for _, v := range names {
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
	}
	return fallback
}

// hostingKeywords hint that an organization is a datacenter/hosting/VPN/cloud (best-effort fallback).
var hostingKeywords = []string{
	"hosting", "host", "data center", "datacenter", "data-center",
	"cloud", "vps", "server", "colocation", "colo", "vpn", "proxy",
	"digitalocean", "linode", "ovh", "hetzner", "vultr", "amazon", "aws",
	"google cloud", "microsoft azure", "azure", "alibaba cloud", "tencent cloud",
}

func looksLikeHosting(org string) bool {
	if org == "" {
		return false
	}
	low := strings.ToLower(org)
	for _, kw := range hostingKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// privateNets are the internal IP ranges. IPs in these ranges are marked IsInternal and NOT looked up in the DB.
var privateNets = func() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
		"::1/128", "fc00::/7", "fe80::/10",
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

func isInternalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
