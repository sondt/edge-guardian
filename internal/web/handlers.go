package web

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
)

// pageData builds the per-request shell context, minting/reading the CSRF token.
func (s *Server) pageData(w http.ResponseWriter, r *http.Request, nav, title string, m Metrics) (PageData, bool) {
	token, err := ensureCSRF(w, r, s.secureCookies())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return PageData{}, false
	}
	return PageData{
		Title:            title,
		Nav:              nav,
		CSRFToken:        token,
		Host:             hostname(),
		State:            m.State,
		UnderAtk:         m.UnderAtk,
		Metrics:          m,
		HealthEnabled:    s.cfg.HealthWindowMins > 0,
		HealthWindowMins: s.cfg.HealthWindowMins,
	}, true
}

// render writes a templ component, mapping a render error to a 500. Centralizes the
// error handling so handlers stay terse.
func (s *Server) render(w http.ResponseWriter, r *http.Request, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := c.Render(r.Context(), w); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

// renderStatus renders with an explicit status code, setting Content-Type BEFORE
// WriteHeader so the header is not silently dropped.
func (s *Server) renderStatus(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := c.Render(r.Context(), w); err != nil {
		// Status/headers already sent; just stop.
		return
	}
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	m := s.store.Snapshot()
	m.Active = len(s.data.Bans())
	pd, ok := s.pageData(w, r, "overview", "Overview", m)
	if !ok {
		return
	}
	events := toEventViews(s.store.Recent(FeedDefault))
	s.render(w, r, Overview(pd, m, events, summarizeSites(s.data.SiteHealth())))
}

func (s *Server) bansPage(w http.ResponseWriter, r *http.Request) {
	m := s.store.Snapshot()
	pd, ok := s.pageData(w, r, "bans", "Banned IPs", m)
	if !ok {
		return
	}
	q := r.URL.Query().Get("q")
	detector := r.URL.Query().Get("detector")
	all := s.safeBans()
	rows := filterBans(all, q, detector, s.now())
	opts := detectorOptions(all)
	s.render(w, r, Bans(pd, rows, opts, q, detector, len(all)))
}

func (s *Server) feedPage(w http.ResponseWriter, r *http.Request) {
	m := s.store.Snapshot()
	pd, ok := s.pageData(w, r, "feed", "Live feed", m)
	if !ok {
		return
	}
	events := toEventViews(s.store.Recent(80))
	s.render(w, r, FeedPage(pd, events))
}

func (s *Server) detectorsPage(w http.ResponseWriter, r *http.Request) {
	m := s.store.Snapshot()
	pd, ok := s.pageData(w, r, "detectors", "Detectors", m)
	if !ok {
		return
	}
	s.render(w, r, DetectorsPage(pd, m))
}

func (s *Server) sitesPage(w http.ResponseWriter, r *http.Request) {
	m := s.store.Snapshot()
	pd, ok := s.pageData(w, r, "sites", "Site health", m)
	if !ok {
		return
	}
	sites := toSiteViews(s.data.SiteHealth())
	s.render(w, r, SitesPage(pd, sites))
}

// pSentinel returns just the Sentinel line fragment for HTMX polling.
func (s *Server) pSentinel(w http.ResponseWriter, r *http.Request) {
	m := s.store.Snapshot()
	s.render(w, r, Sentinel(m))
}

// pReadouts returns the readout cards + state chip fragment for HTMX polling. The
// state chip is updated out-of-band so the top bar stays in sync.
func (s *Server) pReadouts(w http.ResponseWriter, r *http.Request) {
	m := s.store.Snapshot()
	m.Active = len(s.data.Bans())
	s.render(w, r, ReadoutsLive(m))
}

// pFeed returns the recent-feed list fragment for HTMX polling.
func (s *Server) pFeed(w http.ResponseWriter, r *http.Request) {
	events := toEventViews(s.store.Recent(FeedDefault))
	s.render(w, r, FeedList(events))
}

// unban removes a ban and returns an empty replacement for the row plus an OOB swap
// that decrements the banned counter — no page reload.
func (s *Server) unban(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if dec, err := url.PathUnescape(ip); err == nil {
		ip = dec
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		http.Error(w, "missing ip", http.StatusBadRequest)
		return
	}
	if s.data == nil {
		http.Error(w, "daemon unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.data.Unban(r.Context(), ip); err != nil {
		// Surface a small inline error row rather than a blank 500 in the table.
		w.WriteHeader(http.StatusOK)
		s.render(w, r, UnbanError(ip))
		return
	}
	remaining := len(s.safeBans())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	s.render(w, r, UnbanResult(remaining))
}

// safeBans returns the daemon's bans, tolerating a nil DataSource (degraded/offline).
func (s *Server) safeBans() []Ban {
	if s.data == nil {
		return nil
	}
	return s.data.Bans()
}
