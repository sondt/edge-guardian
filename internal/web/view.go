package web

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// pathEscape escapes a single path segment so values like IPv6 addresses are safe in
// a URL.
func pathEscape(s string) string {
	return url.PathEscape(s)
}

// PageData is the shell context every full page render needs: the CSRF token for
// HTMX headers, the active nav key for highlighting, and the live headline state.
type PageData struct {
	Title            string
	Nav              string // "overview" | "bans" | "feed" | "sites" | "detectors"
	CSRFToken        string
	Host             string
	State            string // "Quiet" | "Under scan"
	UnderAtk         bool
	Metrics          Metrics // for the Sentinel line so it renders on first paint, not only after the first poll
	HealthEnabled    bool    // show the "Sites" nav link
	HealthWindowMins int     // window shown on the /sites page
}

// hxHeaders renders the JSON object passed to HTMX's hx-headers attribute so every
// poll/POST carries the CSRF token. Built here (not in the template) to keep escaping
// correct and in one place.
func (p PageData) hxHeaders() string {
	// The token is base64url (no quotes/backslashes), safe to embed directly.
	return `{"` + csrfHeader + `":"` + p.CSRFToken + `"}`
}

// banView is a ledger row prepared for rendering: raw Ban plus humanized fields so the
// template stays logic-free.
type banView struct {
	Ban
	Origin      string // "CN · AS4837" or "—"
	FirstSeenHM string // "09:41:02"
	Expires     string // "in 6d23h" / "expired"
	Expired     bool
}

func toBanView(b Ban, now time.Time) banView {
	return banView{
		Ban:         b,
		Origin:      originText(b.Country, b.ASN),
		FirstSeenHM: clock(b.FirstSeen),
		Expires:     humanizeUntil(b.ExpiresAt, now),
		Expired:     !b.ExpiresAt.IsZero() && !now.Before(b.ExpiresAt),
	}
}

// eventView is a feed row prepared for rendering.
type eventView struct {
	Event
	TimeHM   string
	Origin   string
	Banned   bool
	WouldBan bool
}

func toEventView(e Event) eventView {
	return eventView{
		Event:    e,
		TimeHM:   stamp(e.At),
		Origin:   originText(e.Country, e.ASN),
		Banned:   e.Action == "banned",
		WouldBan: e.Action != "banned",
	}
}

func toEventViews(events []Event) []eventView {
	out := make([]eventView, 0, len(events))
	for _, e := range events {
		out = append(out, toEventView(e))
	}
	return out
}

// filterBans applies the ledger search box and detector filter, then sorts newest-ban
// first for a stable order. q matches IP, ASN or country (case-insensitive substring).
func filterBans(bans []Ban, q, detector string, now time.Time) []banView {
	q = strings.ToLower(strings.TrimSpace(q))
	detector = strings.TrimSpace(detector)
	out := make([]banView, 0, len(bans))
	for _, b := range bans {
		if detector != "" && b.Detector != detector {
			continue
		}
		if q != "" && !banMatches(b, q) {
			continue
		}
		out = append(out, toBanView(b, now))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].FirstSeen.After(out[j].FirstSeen)
	})
	return out
}

func banMatches(b Ban, q string) bool {
	return strings.Contains(strings.ToLower(b.IP), q) ||
		strings.Contains(strings.ToLower(b.ASN), q) ||
		strings.Contains(strings.ToLower(b.Country), q)
}

// detectorOptions returns the distinct detectors present in the ban list, sorted, for
// the filter dropdown.
func detectorOptions(bans []Ban) []string {
	set := map[string]struct{}{}
	for _, b := range bans {
		if b.Detector != "" {
			set[b.Detector] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func originText(country, asn string) string {
	country = strings.TrimSpace(country)
	asn = strings.TrimSpace(asn)
	switch {
	case country != "" && asn != "":
		return country + " · " + asn
	case asn != "":
		return asn
	case country != "":
		return country
	default:
		return "—"
	}
}

func clock(t time.Time) string {
	if t.IsZero() {
		return "--:--:--"
	}
	return t.Format("15:04:05")
}

// stamp formats an event timestamp with the date so rows spanning hours/days are
// unambiguous, e.g. "Jun 14 07:06:13".
func stamp(t time.Time) string {
	if t.IsZero() {
		return "-- --:--:--"
	}
	return t.Format("Jan 02 15:04:05")
}

// humanizeUntil renders a coarse countdown like "in 6d23h" or "in 14m". Past times
// read "expired". Kept coarse on purpose — the ledger is a glance, not a stopwatch.
func humanizeUntil(t, now time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := t.Sub(now)
	if d <= 0 {
		return "expired"
	}
	days := int(d / (24 * time.Hour))
	hours := int((d % (24 * time.Hour)) / time.Hour)
	mins := int((d % time.Hour) / time.Minute)
	switch {
	case days > 0:
		return fmt.Sprintf("in %dd%dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("in %dh%dm", hours, mins)
	case mins > 0:
		return fmt.Sprintf("in %dm", mins)
	default:
		return "in <1m"
	}
}

// pct renders a 0..1 fraction as a whole-percent string, e.g. 0.713 → "71%".
func pct(share float64) string {
	return fmt.Sprintf("%d%%", int(share*100+0.5))
}

// sparkPath builds an SVG polyline `points` string for a sparkline from integer
// counts, scaled into a w×h box. Returns "" for an empty/flat-zero series so the
// template can show a baseline instead.
func sparkPath(counts []int, w, h float64) string {
	if len(counts) == 0 {
		return ""
	}
	max := 0
	for _, c := range counts {
		if c > max {
			max = c
		}
	}
	if max == 0 {
		return ""
	}
	n := len(counts)
	var b strings.Builder
	for i, c := range counts {
		x := 0.0
		if n > 1 {
			x = float64(i) / float64(n-1) * w
		}
		y := h - (float64(c)/float64(max))*h
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y)
	}
	return b.String()
}
