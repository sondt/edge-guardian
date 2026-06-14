package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// authedGet performs an authenticated GET and returns the recorder.
func authedGet(t *testing.T, s *Server, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestBansPageRendersLedgerAndFolds(t *testing.T) {
	now := time.Now()
	data := &fakeDataSource{bans: []Ban{
		{IP: "185.1.2.3", Detector: "http", FirstSeen: now, ExpiresAt: now.Add(6 * 24 * time.Hour), Country: "CN", ASN: "AS4837", Hits: 12},
		{IP: "92.4.5.6", Detector: "portscan", FirstSeen: now.Add(-time.Minute), ExpiresAt: now.Add(-time.Hour), Country: "RU", ASN: "AS1299", Hits: 3},
	}}
	s := newTestServer(t, data)
	cookies := login(t, s)

	rec := authedGet(t, s, "/bans", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("bans: want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Banned IPs", "185.1.2.3", "AS4837", "Unban", `data-label="IP"`, "expired"} {
		if !strings.Contains(body, want) {
			t.Fatalf("bans body missing %q", want)
		}
	}
}

func TestBansPageFilterAndEmptyStates(t *testing.T) {
	s := newTestServer(t, &fakeDataSource{})
	cookies := login(t, s)

	// Empty store → inviting empty state.
	rec := authedGet(t, s, "/bans", cookies)
	if !strings.Contains(rec.Body.String(), "No bans yet. edge-guardian is watching.") {
		t.Fatalf("expected empty-state copy")
	}

	// With bans but a non-matching filter → "no match" state.
	data := &fakeDataSource{bans: []Ban{{IP: "1.2.3.4", Detector: "http"}}}
	s2 := newTestServer(t, data)
	cookies2 := login(t, s2)
	rec2 := authedGet(t, s2, "/bans?q=zzzznomatch", cookies2)
	if !strings.Contains(rec2.Body.String(), "No bans match your filter.") {
		t.Fatalf("expected no-match state, got: %s", rec2.Body.String())
	}
}

func TestFeedAndDetectorsPagesRender(t *testing.T) {
	now := time.Now()
	store := NewStore(time.Hour)
	store.Push(Event{At: now, IP: "1.1.1.1", Detector: "http", Action: "banned", Country: "CN", ASN: "AS4837"})
	store.Push(Event{At: now, IP: "2.2.2.2", Detector: "portscan", Action: "would-ban", Country: "RU", ASN: "AS1299"})
	s := New(testConfig(t), &fakeDataSource{}, store)
	cookies := login(t, s)

	rec := authedGet(t, s, "/feed", cookies)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Live feed") {
		t.Fatalf("feed page render failed: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "would") {
		t.Fatalf("feed should show would-ban tag")
	}

	recD := authedGet(t, s, "/detectors", cookies)
	if recD.Code != http.StatusOK {
		t.Fatalf("detectors: %d", recD.Code)
	}
	for _, d := range []string{"http", "portscan", "honeypot", "sshd"} {
		if !strings.Contains(recD.Body.String(), d) {
			t.Fatalf("detectors page missing %q", d)
		}
	}
}

func TestFeedEmptyState(t *testing.T) {
	s := newTestServer(t, &fakeDataSource{})
	cookies := login(t, s)
	rec := authedGet(t, s, "/feed", cookies)
	if !strings.Contains(rec.Body.String(), "Quiet on the wire.") {
		t.Fatalf("expected empty feed state")
	}
}

func TestSentinelPartialRendersSVGTicks(t *testing.T) {
	now := time.Now()
	store := NewStore(time.Hour)
	store.now = fixedClock(now)
	// One banned (solid) + a separate would-ban (hollow) so both tick paths render.
	store.Push(Event{At: now.Add(-30 * time.Second), IP: "9.9.9.9", Detector: "honeypot", Action: "banned"})
	store.Push(Event{At: now.Add(-time.Minute), IP: "8.8.8.8", Detector: "http", Action: "would-ban"})
	s := New(testConfig(t), &fakeDataSource{}, store)
	cookies := login(t, s)

	rec := authedGet(t, s, "/_p/sentinel", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("sentinel partial: %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"<svg", "sentinel__tick--solid", "sentinel__tick--hollow", "opacity:"} {
		if !strings.Contains(body, want) {
			t.Fatalf("sentinel SVG missing %q\n%s", want, body)
		}
	}
}

func TestReadoutsPartialOOBChip(t *testing.T) {
	now := time.Now()
	store := NewStore(time.Hour)
	store.now = fixedClock(now)
	for i := 0; i < scanThreshold+1; i++ {
		store.Push(Event{At: now.Add(-time.Second), IP: "9.9.9.9", Detector: "portscan", Action: "banned"})
	}
	s := New(testConfig(t), &fakeDataSource{}, store)
	cookies := login(t, s)

	rec := authedGet(t, s, "/_p/readouts", cookies)
	body := rec.Body.String()
	if !strings.Contains(body, `hx-swap-oob`) {
		t.Fatalf("readouts partial should carry OOB chip swap")
	}
	if !strings.Contains(body, "Under scan") {
		t.Fatalf("expected Under scan chip in readouts")
	}
}

func TestUnbanIPv6PathEscaped(t *testing.T) {
	data := &fakeDataSource{bans: []Ban{{IP: "2001:db8::1", Detector: "http"}}}
	s := newTestServer(t, data)
	cookies := login(t, s)
	token := csrfTokenFrom(cookies)

	rec := httptest.NewRecorder()
	// %3A is ':' escaped — handler must unescape it back to the raw IPv6.
	req := httptest.NewRequest(http.MethodPost, "/bans/2001%3Adb8%3A%3A1/unban", nil)
	req.Header.Set(csrfHeader, token)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ipv6 unban: want 200, got %d", rec.Code)
	}
	data.mu.Lock()
	defer data.mu.Unlock()
	if len(data.unbanned) != 1 || data.unbanned[0] != "2001:db8::1" {
		t.Fatalf("ipv6 not unescaped correctly: %+v", data.unbanned)
	}
}

func TestUnbanNilDataSource(t *testing.T) {
	s := New(testConfig(t), nil, NewStore(time.Hour))
	cookies := login(t, s)
	token := csrfTokenFrom(cookies)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/bans/1.2.3.4/unban", nil)
	req.Header.Set(csrfHeader, token)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil datasource unban: want 503, got %d", rec.Code)
	}
}

func TestLogoutClearsSession(t *testing.T) {
	s := newTestServer(t, &fakeDataSource{})
	cookies := login(t, s)
	token := csrfTokenFrom(cookies)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set(csrfHeader, token)
	req.Header.Set("HX-Request", "true")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	s.Handler().ServeHTTP(rec, req)
	if rec.Header().Get("HX-Redirect") != "/login" {
		t.Fatalf("logout should HX-Redirect to login")
	}
}

func TestSessionTokenValidation(t *testing.T) {
	cfg := testConfig(t)
	a, err := newAuthenticator(cfg)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	now := time.Now()
	tok := a.issue(now)
	if !a.valid(tok, now) {
		t.Fatal("freshly issued token should be valid")
	}
	if a.valid(tok, now.Add(sessionTTL+time.Minute)) {
		t.Fatal("expired token should be invalid")
	}
	if a.valid("garbage", now) {
		t.Fatal("garbage token should be invalid")
	}
	if a.valid(tok+"x", now) {
		t.Fatal("tampered token should be invalid")
	}
}

func TestAuthVerifyGoodCredentials(t *testing.T) {
	cfg := testConfig(t)
	a, _ := newAuthenticator(cfg)
	if !a.verify(testUser, testPassword) {
		t.Fatal("correct credentials should verify")
	}
	if a.verify("wrong", testPassword) {
		t.Fatal("wrong username should fail")
	}
	if a.verify(testUser, "wrong") {
		t.Fatal("wrong password should fail")
	}
}

func TestStartRejectsBadAddress(t *testing.T) {
	cfg := testConfig(t)
	cfg.Listen = "127.0.0.1:not-a-port"
	s := New(cfg, &fakeDataSource{}, NewStore(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := s.Start(ctx)
	if err == nil {
		t.Fatal("Start should return an error for an invalid listen address")
	}
}
