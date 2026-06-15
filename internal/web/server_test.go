package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// fakeDataSource is a test double for the daemon's data source. It records unban calls
// and lets a test seed bans. Safe for concurrent use.
type fakeDataSource struct {
	mu       sync.Mutex
	bans     []Ban
	unbanned []string
	failUnup bool // when true, Unban returns an error
	sites    []SiteHealth
}

func (f *fakeDataSource) SiteHealth() []SiteHealth {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]SiteHealth, len(f.sites))
	copy(out, f.sites)
	return out
}

func (f *fakeDataSource) Bans() []Ban {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Ban, len(f.bans))
	copy(out, f.bans)
	return out
}

func (f *fakeDataSource) Unban(_ context.Context, ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failUnup {
		return errUnban
	}
	f.unbanned = append(f.unbanned, ip)
	// Remove from bans so the counter reflects the change.
	kept := f.bans[:0]
	for _, b := range f.bans {
		if b.IP != ip {
			kept = append(kept, b)
		}
	}
	f.bans = kept
	return nil
}

var errUnban = &unbanErr{}

type unbanErr struct{}

func (*unbanErr) Error() string { return "unban failed" }

// testPassword and its bcrypt hash are used across auth tests.
const testUser = "admin"
const testPassword = "correct horse battery staple"

func testConfig(t *testing.T) Config {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return Config{Enabled: true, Listen: DefaultListen, Username: testUser, PasswordHash: string(hash)}
}

func newTestServer(t *testing.T, data DataSource) *Server {
	t.Helper()
	store := NewStore(time.Hour)
	return New(testConfig(t), data, store)
}

// login performs a real login against the handler and returns the session + csrf
// cookies so subsequent authenticated requests can be made.
func login(t *testing.T, s *Server) []*http.Cookie {
	t.Helper()
	// First GET /login to obtain a CSRF cookie + token.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	s.Handler().ServeHTTP(rec, req)
	csrfCookies := rec.Result().Cookies()
	token := ""
	body := rec.Body.String()
	if i := strings.Index(body, `name="csrf_token" value="`); i >= 0 {
		rest := body[i+len(`name="csrf_token" value="`):]
		if j := strings.Index(rest, `"`); j >= 0 {
			token = rest[:j]
		}
	}
	if token == "" {
		t.Fatal("could not extract csrf token from login form")
	}

	form := "username=" + testUser + "&password=" + strings.ReplaceAll(testPassword, " ", "+") + "&csrf_token=" + token
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range csrfCookies {
		req2.AddCookie(c)
	}
	s.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusSeeOther {
		t.Fatalf("login POST: want 303, got %d (%s)", rec2.Code, rec2.Body.String())
	}
	// Merge cookies: csrf from step 1 + session from step 2.
	all := append([]*http.Cookie{}, csrfCookies...)
	all = append(all, rec2.Result().Cookies()...)
	return all
}

func csrfTokenFrom(cookies []*http.Cookie) string {
	for _, c := range cookies {
		if c.Name == csrfCookie {
			return c.Value
		}
	}
	return ""
}

func TestServerNameAndDefaults(t *testing.T) {
	s := New(Config{}, &fakeDataSource{}, nil)
	if s.Name() != "dashboard" {
		t.Fatalf("Name = %q, want dashboard", s.Name())
	}
	if s.cfg.Listen != DefaultListen {
		t.Fatalf("Listen default = %q, want %q", s.cfg.Listen, DefaultListen)
	}
}

func TestNeverDefaultsToWildcard(t *testing.T) {
	s := New(Config{Listen: ""}, &fakeDataSource{}, nil)
	if strings.HasPrefix(s.cfg.Listen, "0.0.0.0") {
		t.Fatalf("must never default to 0.0.0.0, got %q", s.cfg.Listen)
	}
	if !isLoopbackListen(s.cfg.Listen) {
		t.Fatalf("default listen must be loopback, got %q", s.cfg.Listen)
	}
}

func TestAuthRequiredOnProtectedRoutes(t *testing.T) {
	s := newTestServer(t, &fakeDataSource{})
	for _, path := range []string{"/", "/bans", "/feed", "/detectors", "/_p/sentinel", "/_p/readouts", "/_p/feed"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s without auth: want 303 redirect, got %d", path, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login" {
			t.Fatalf("%s should redirect to /login, got %q", path, loc)
		}
	}
}

func TestHTMXUnauthGetsRedirectHeader(t *testing.T) {
	s := newTestServer(t, &fakeDataSource{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_p/readouts", nil)
	req.Header.Set("HX-Request", "true")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("HTMX unauth: want 401, got %d", rec.Code)
	}
	if rec.Header().Get("HX-Redirect") != "/login" {
		t.Fatalf("missing HX-Redirect header")
	}
}

func TestCSPHeaderPresent(t *testing.T) {
	s := newTestServer(t, &fakeDataSource{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	s.Handler().ServeHTTP(rec, req)
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP missing %q; got %q", want, csp)
		}
	}
	// script-src must stay strict (no inline scripts) — the high-value protection.
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("script-src must NOT allow unsafe-inline; got %q", csp)
	}
	// style-src must allow inline (HTMX + data-driven tick/bar styles need it).
	if !strings.Contains(csp, "style-src 'self' 'unsafe-inline'") {
		t.Fatalf("style-src must allow 'unsafe-inline'; got %q", csp)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing nosniff header")
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	s := newTestServer(t, &fakeDataSource{})
	// Obtain csrf.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	cookies := rec.Result().Cookies()
	token := csrfTokenFrom(cookies)

	form := "username=admin&password=wrong&csrf_token=" + token
	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	s.Handler().ServeHTTP(rec2, req)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("bad creds: want 401, got %d", rec2.Code)
	}
}

func TestLoginRejectsMissingCSRF(t *testing.T) {
	s := newTestServer(t, &fakeDataSource{})
	form := "username=admin&password=" + strings.ReplaceAll(testPassword, " ", "+")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF on login: want 403, got %d", rec.Code)
	}
}

func TestAuthenticatedOverviewRenders(t *testing.T) {
	s := newTestServer(t, &fakeDataSource{})
	cookies := login(t, s)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("overview: want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Recent") || !strings.Contains(body, "sentinel") {
		t.Fatalf("overview body missing expected content")
	}
}

func TestUnbanHappyPath(t *testing.T) {
	now := time.Now()
	data := &fakeDataSource{bans: []Ban{
		{IP: "185.1.2.3", Detector: "http", FirstSeen: now, ExpiresAt: now.Add(24 * time.Hour)},
		{IP: "92.4.5.6", Detector: "portscan", FirstSeen: now, ExpiresAt: now.Add(24 * time.Hour)},
	}}
	s := newTestServer(t, data)
	cookies := login(t, s)
	token := csrfTokenFrom(cookies)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/bans/185.1.2.3/unban", nil)
	req.Header.Set(csrfHeader, token)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unban: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	data.mu.Lock()
	defer data.mu.Unlock()
	if len(data.unbanned) != 1 || data.unbanned[0] != "185.1.2.3" {
		t.Fatalf("unban not recorded: %+v", data.unbanned)
	}
	body := rec.Body.String()
	// OOB counter update should reflect 1 remaining.
	if !strings.Contains(body, `id="ban-count"`) || !strings.Contains(body, "1") {
		t.Fatalf("unban response missing OOB counter: %s", body)
	}
}

func TestBansPageShowsLocationAndFullPath(t *testing.T) {
	now := time.Now()
	longPath := "/cgi-bin/magicBox.cgi/action/getSnapshot/very/long/probe/path/that/exceeds/the/old/limit"
	data := &fakeDataSource{bans: []Ban{{
		IP: "103.3.60.114", Detector: "http", Reason: longPath,
		FirstSeen: now, ExpiresAt: now.Add(24 * time.Hour),
		Country: "SG", ASN: "AS63949 Akamai", Location: "Singapore",
	}}}
	s := newTestServer(t, data)
	cookies := login(t, s)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/bans", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /bans: want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	// The full path must be present verbatim (no server-side truncation) and the GeoIP
	// location must render alongside the network origin.
	for _, want := range []string{longPath, "Singapore", "AS63949 Akamai"} {
		if !strings.Contains(body, want) {
			t.Fatalf("bans page missing %q", want)
		}
	}
}

func TestErrorsPageRendersWithFilter(t *testing.T) {
	s := newTestServer(t, &fakeDataSource{})
	base := time.Now().Add(-time.Hour)
	s.store.PushError(ErrorReq{At: base.Add(1 * time.Minute), Host: "shop.example.com", IP: "9.9.9.9", Path: "/wp-login.php", Status: 403})
	s.store.PushError(ErrorReq{At: base.Add(2 * time.Minute), Host: "api.example.com", IP: "8.8.8.8", Path: "/v1/orders", Status: 502})
	cookies := login(t, s)

	// Unfiltered: both rows + the host options present.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/errors", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /errors: want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"/wp-login.php", "/v1/orders", "shop.example.com", "api.example.com", "502", "403"} {
		if !strings.Contains(body, want) {
			t.Fatalf("errors page missing %q", want)
		}
	}

	// Filter by 5xx: only the 502 row should remain.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/errors?class=5xx", nil)
	for _, c := range cookies {
		req2.AddCookie(c)
	}
	s.Handler().ServeHTTP(rec2, req2)
	body2 := rec2.Body.String()
	if !strings.Contains(body2, "/v1/orders") || strings.Contains(body2, "/wp-login.php") {
		t.Fatalf("5xx filter wrong:\n%s", body2)
	}
}

func TestUnbanRejectedWithoutCSRF(t *testing.T) {
	data := &fakeDataSource{bans: []Ban{{IP: "185.1.2.3", Detector: "http"}}}
	s := newTestServer(t, data)
	cookies := login(t, s)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/bans/185.1.2.3/unban", nil)
	for _, c := range cookies {
		req.AddCookie(c) // session + csrf cookie present, but no header token
	}
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unban without CSRF header: want 403, got %d", rec.Code)
	}
}

func TestUnbanErrorRendersInlineRow(t *testing.T) {
	data := &fakeDataSource{bans: []Ban{{IP: "185.1.2.3"}}, failUnup: true}
	s := newTestServer(t, data)
	cookies := login(t, s)
	token := csrfTokenFrom(cookies)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/bans/185.1.2.3/unban", nil)
	req.Header.Set(csrfHeader, token)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unban error: want 200 with inline row, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Couldn") {
		t.Fatalf("expected inline error message in row")
	}
}

func TestStaticAssetsServed(t *testing.T) {
	s := newTestServer(t, &fakeDataSource{})
	for _, path := range []string{"/static/app.css", "/static/htmx.min.js", "/static/app.js"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("static %s: want 200, got %d", path, rec.Code)
		}
		if rec.Header().Get("Cache-Control") == "" {
			t.Fatalf("static %s missing cache header", path)
		}
	}
}

func TestPartialsRenderHTMLNotJSON(t *testing.T) {
	data := &fakeDataSource{}
	s := newTestServer(t, data)
	cookies := login(t, s)
	for _, path := range []string{"/_p/sentinel", "/_p/readouts", "/_p/feed"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("HX-Request", "true")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d", path, rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if !strings.Contains(ct, "text/html") {
			t.Fatalf("%s should be text/html, got %q", path, ct)
		}
	}
}

func TestStartGracefulShutdown(t *testing.T) {
	// Bind an ephemeral loopback port so the test never conflicts.
	cfg := testConfig(t)
	cfg.Listen = "127.0.0.1:0"
	s := New(cfg, &fakeDataSource{}, NewStore(time.Hour))
	// Start with a context we cancel immediately; Start should return nil.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error on shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}
}
