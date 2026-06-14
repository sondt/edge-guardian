package web

import (
	"net/http"
)

// cspPolicy is the Content-Security-Policy. script-src stays strict 'self' (no inline
// scripts — that is the high-value XSS protection). style-src needs 'unsafe-inline'
// because (a) HTMX applies inline styles for indicators/transitions, and (b) the
// dashboard renders data-driven inline styles (Sentinel tick height/opacity, bar
// widths). Those values are server-computed numerics — never attacker-controlled
// strings — and CSP hashes/nonces do not apply to style *attributes*, so 'unsafe-inline'
// is the correct, conventional relaxation here. Everything else stays 'self'; data: is
// allowed for images.
const cspPolicy = "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// securityHeaders sets the CSP and a few hardening headers on every response. Applied
// to all routes including static assets and the login page.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", cspPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// requireAuth gates a route group behind a valid session. Unauthenticated browser
// requests are redirected to /login; unauthenticated HTMX requests get a 401 with an
// HX-Redirect header so the polling fragments bounce the user to login cleanly.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.auth.authedFromRequest(r, s.now()) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/login")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

// requireCSRF gates state-changing requests behind the double-submit token check. It
// runs only for unsafe methods; safe methods pass through untouched.
func requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if !verifyCSRF(r) {
			http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
