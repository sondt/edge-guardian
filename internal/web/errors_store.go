package web

import (
	"sort"
	"strings"
	"time"
)

// ErrorReq is one error response (4xx/5xx) observed in the access log, kept for the
// /errors page. Host is empty when the log format carries no $host.
type ErrorReq struct {
	At     time.Time
	Host   string
	IP     string
	Path   string
	Status int
}

// ErrorsDefaultPerPage is the default page size for the /errors table.
const ErrorsDefaultPerPage = 50

// ErrorFilter narrows and paginates the error log. Empty fields mean "no filter".
type ErrorFilter struct {
	Host   string // exact host match
	Class  string // "4xx" | "5xx" | "" (any)
	Search string // case-insensitive substring of path or IP
	Page   int    // 1-based; <1 normalized to 1
}

// ErrorPage is one rendered page of filtered errors plus the metadata the UI needs for
// pagination controls and the host filter dropdown.
type ErrorPage struct {
	Items    []ErrorReq // newest first
	Total    int        // matches after filtering (before pagination)
	Page     int        // current page (1-based)
	Pages    int        // total pages
	PerPage  int
	Hosts    []string // distinct hosts present in the buffer, sorted (for the filter)
	Filter   ErrorFilter
	TotalAll int // total errors retained (before filtering)
}

// PushError records one error request, dropping the oldest when the buffer is full.
func (s *Store) PushError(e ErrorReq) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.At.IsZero() {
		e.At = s.now()
	}
	s.errs = append(s.errs, e)
	if len(s.errs) > ErrorBufferCap {
		// Drop the oldest overflow; compact in place to keep the slice bounded.
		drop := len(s.errs) - ErrorBufferCap
		copy(s.errs, s.errs[drop:])
		s.errs = s.errs[:ErrorBufferCap]
	}
}

// Errors returns a filtered, paginated view of the retained error requests, newest
// first. It also returns the distinct host set so the UI can offer a host filter.
func (s *Store) Errors(f ErrorFilter) ErrorPage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	perPage := ErrorsDefaultPerPage
	hosts := distinctHosts(s.errs)

	search := strings.ToLower(strings.TrimSpace(f.Search))
	matched := make([]ErrorReq, 0, len(s.errs))
	for _, e := range s.errs {
		if f.Host != "" && e.Host != f.Host {
			continue
		}
		if f.Class != "" && statusClassOf(e.Status) != f.Class {
			continue
		}
		if search != "" &&
			!strings.Contains(strings.ToLower(e.Path), search) &&
			!strings.Contains(strings.ToLower(e.IP), search) {
			continue
		}
		matched = append(matched, e)
	}

	// Newest first.
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].At.After(matched[j].At) })

	total := len(matched)
	pages := max((total+perPage-1)/perPage, 1)
	page := min(max(f.Page, 1), pages)
	start := (page - 1) * perPage
	end := start + perPage
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	return ErrorPage{
		Items:    matched[start:end],
		Total:    total,
		Page:     page,
		Pages:    pages,
		PerPage:  perPage,
		Hosts:    hosts,
		Filter:   f,
		TotalAll: len(s.errs),
	}
}

// statusClassOf maps an HTTP status to "4xx"/"5xx"/"" (anything else).
func statusClassOf(status int) string {
	switch {
	case status >= 500 && status < 600:
		return "5xx"
	case status >= 400 && status < 500:
		return "4xx"
	default:
		return ""
	}
}

// distinctHosts returns the sorted set of non-empty hosts seen in the buffer.
func distinctHosts(errs []ErrorReq) []string {
	set := make(map[string]struct{})
	for _, e := range errs {
		if e.Host != "" {
			set[e.Host] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
