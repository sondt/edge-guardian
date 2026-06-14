// Package blocklist fetches and parses public IP blocklists (FireHOL, Spamhaus
// DROP, ...) into prefix lists, to be loaded PROACTIVELY into nftables — blocking
// known-bad sources before they ever reach the server.
package blocklist

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
)

// Set is the merged result of several blocklists, split by address family and deduplicated.
type Set struct {
	V4 []netip.Prefix
	V6 []netip.Prefix
}

// Len returns the total number of prefixes.
func (s Set) Len() int { return len(s.V4) + len(s.V6) }

// parseLine extracts a prefix from a single blocklist line. It supports:
//   - FireHOL netset: "1.2.3.0/24" or "1.2.3.4" per line, "#" comments.
//   - Spamhaus DROP: "1.2.3.0/24 ; SBL123" (CIDR then "; description").
//
// Empty/comment lines ("#" or ";") → skipped. A bare IP → /32 (v4) or /128 (v6).
func parseLine(line string) (netip.Prefix, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == ';' {
		return netip.Prefix{}, false
	}
	// Take the first token (before whitespace or ";").
	tok := line
	if i := strings.IndexAny(tok, " \t;"); i >= 0 {
		tok = tok[:i]
	}
	if p, err := netip.ParsePrefix(tok); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(tok); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// Parse reads a blocklist (text) into a list of prefixes.
func Parse(r io.Reader) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if p, ok := parseLine(sc.Text()); ok {
			out = append(out, p)
		}
	}
	return out
}

// Fetch downloads a URL and parses it into prefixes.
func Fetch(ctx context.Context, client *http.Client, url string) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request %q: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %q: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %q: status %d", url, resp.StatusCode)
	}
	// Limit to 32MB to guard against a malicious/corrupt source.
	return Parse(io.LimitReader(resp.Body, 32<<20)), nil
}

// excluder reports whether a prefix is in the allowlist (so it is NOT blocked).
type excluder interface {
	Contains(netip.Addr) bool
}

// FetchAll downloads all sources, merges them, deduplicates, drops prefixes whose network
// address is in the allowlist, then splits into v4/v6. A failing source is skipped (its
// error is returned in the error list) so the other sources remain usable.
func FetchAll(ctx context.Context, client *http.Client, urls []string, allow excluder) (Set, []error) {
	seen := make(map[netip.Prefix]struct{})
	var set Set
	var errs []error

	for _, url := range urls {
		prefixes, err := Fetch(ctx, client, url)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, p := range prefixes {
			if _, dup := seen[p]; dup {
				continue
			}
			if allow != nil && allow.Contains(p.Addr()) {
				continue // don't block an allowlisted range
			}
			seen[p] = struct{}{}
			if p.Addr().Is4() {
				set.V4 = append(set.V4, p)
			} else {
				set.V6 = append(set.V6, p)
			}
		}
	}
	sortPrefixes(set.V4)
	sortPrefixes(set.V6)
	return set, errs
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}
