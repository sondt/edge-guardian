package web

import (
	"fmt"
	"net/url"
	"strconv"
)

// errorView is one ErrorReq prepared for rendering: humanized time + status styling so
// the template stays logic-free. Mirrors banView/eventView.
type errorView struct {
	TimeHM     string
	Host       string // "—" when the log has no $host
	IP         string
	Path       string
	Status     string
	StatusKind string // "is-4xx" | "is-5xx" — CSS tone
	Origin     string // "US · AS8075 …" or "—" (GeoIP)
	Location   string // "City, Region, Country" or "" (GeoIP)
	UA         string // user-agent or "—"
}

func toErrorView(e ErrorReq) errorView {
	return errorView{
		TimeHM:     stamp(e.At),
		Host:       orDash(e.Host),
		IP:         orDash(e.IP),
		Path:       orDash(e.Path),
		Status:     strconv.Itoa(e.Status),
		StatusKind: "is-" + statusClassOf(e.Status),
		Origin:     originText(e.Country, e.ASN),
		Location:   e.Location,
		UA:         orDash(e.UA),
	}
}

func toErrorViews(errs []ErrorReq) []errorView {
	out := make([]errorView, 0, len(errs))
	for _, e := range errs {
		out = append(out, toErrorView(e))
	}
	return out
}

// errorPageURL builds a /errors link preserving the active filters while changing one
// parameter (page navigation / filter links).
func errorPageURL(f ErrorFilter, page int) string {
	q := url.Values{}
	if f.Host != "" {
		q.Set("host", f.Host)
	}
	if f.Class != "" {
		q.Set("class", f.Class)
	}
	if f.Search != "" {
		q.Set("q", f.Search)
	}
	if page > 1 {
		q.Set("page", strconv.Itoa(page))
	}
	if len(q) == 0 {
		return "/errors"
	}
	return "/errors?" + q.Encode()
}

// errorRangeLabel renders the "X–Y of N" summary for the current page.
func errorRangeLabel(p ErrorPage) string {
	if p.Total == 0 {
		return "0 of 0"
	}
	start := (p.Page-1)*p.PerPage + 1
	end := start + len(p.Items) - 1
	return fmt.Sprintf("%d–%d of %d", start, end, p.Total)
}
