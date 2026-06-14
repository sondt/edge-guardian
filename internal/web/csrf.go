package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"
)

// csrfCookie is the name of the double-submit cookie holding the CSRF token.
const csrfCookie = "nsg_csrf"

// csrfHeader is the request header HTMX sends the token in (via hx-headers).
const csrfHeader = "X-CSRF-Token"

// csrfTokenBytes is the entropy of a CSRF token before base64 encoding.
const csrfTokenBytes = 32

// newCSRFToken returns a fresh URL-safe random token. crypto/rand is used because the
// token is a security boundary; a predictable token would defeat CSRF protection.
func newCSRFToken() (string, error) {
	buf := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// ensureCSRF reads the CSRF cookie or, if absent/empty, mints a new token and sets the
// cookie on the response. It returns the token to embed in the page <meta>. The cookie
// is HttpOnly=false intentionally is NOT needed: with double-submit the JS never reads
// the cookie; HTMX sends the token from the meta tag instead, so we keep it HttpOnly.
func ensureCSRF(w http.ResponseWriter, r *http.Request, secure bool) (string, error) {
	if c, err := r.Cookie(csrfCookie); err == nil && c.Value != "" {
		return c.Value, nil
	}
	token, err := newCSRFToken()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(12 * time.Hour),
	})
	return token, nil
}

// verifyCSRF performs the double-submit check: the token in the request header must
// equal the token in the cookie. Comparison is constant-time. Returns true if valid.
func verifyCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	if err != nil || c.Value == "" {
		return false
	}
	got := r.Header.Get(csrfHeader)
	if got == "" {
		// Fall back to a form field so non-HTMX POSTs (e.g. the login form) work.
		got = r.PostFormValue("csrf_token")
	}
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(got)) == 1
}
