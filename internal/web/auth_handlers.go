package web

import (
	"net/http"
	"os"
)

// hostname returns the machine hostname for the top bar, or "host" if unavailable.
func hostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "host"
}

// loginForm renders the login page. Already-authenticated users are sent home.
func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if s.auth.authedFromRequest(r, s.now()) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	token, err := ensureCSRF(w, r, s.secureCookies())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, r, LoginPage(token, false))
}

// loginSubmit verifies credentials and, on success, issues a session cookie. CSRF is
// enforced here directly (the login route sits outside the protected group) using the
// double-submit form field.
func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !verifyCSRF(r) {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	ip := clientIP(r)
	if !s.limiter.allow(ip, s.now()) {
		http.Error(w, "too many login attempts; try again later", http.StatusTooManyRequests)
		return
	}

	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	if !s.auth.verify(username, password) {
		token, err := ensureCSRF(w, r, s.secureCookies())
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.renderStatus(w, r, http.StatusUnauthorized, LoginPage(token, true))
		return
	}

	// Successful login: clear the throttle for this IP so a legit user isn't penalized.
	s.limiter.reset(ip)
	setSession(w, s.auth.issue(s.now()), s.secureCookies())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// logout clears the session cookie and returns to login. CSRF-protected via the
// double-submit header/field.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !verifyCSRF(r) {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return
	}
	clearSession(w, s.secureCookies())
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/login")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
