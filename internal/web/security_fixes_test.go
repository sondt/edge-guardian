package web

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestLoginLimiter(t *testing.T) {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	l := newLoginLimiter(2, time.Minute)

	if !l.allow("ip1", base) {
		t.Fatal("1st attempt should be allowed")
	}
	if !l.allow("ip1", base.Add(time.Second)) {
		t.Fatal("2nd attempt should be allowed")
	}
	if l.allow("ip1", base.Add(2*time.Second)) {
		t.Fatal("3rd attempt should be blocked")
	}
	// A different key is independent.
	if !l.allow("ip2", base.Add(2*time.Second)) {
		t.Fatal("other ip should be allowed")
	}
	// After the window slides, attempts are allowed again.
	if !l.allow("ip1", base.Add(2*time.Minute)) {
		t.Fatal("attempt after window should be allowed")
	}
	// reset clears the throttle immediately.
	l2 := newLoginLimiter(1, time.Minute)
	l2.allow("ip1", base)
	if l2.allow("ip1", base.Add(time.Second)) {
		t.Fatal("should be blocked after 1")
	}
	l2.reset("ip1")
	if !l2.allow("ip1", base.Add(2*time.Second)) {
		t.Fatal("reset should clear the throttle")
	}
}

// TestSessionToken_UsernameWithPipe guards the fix for a username containing the '|'
// delimiter previously corrupting the session token layout.
func TestSessionToken_UsernameWithPipe(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	a, err := newAuthenticator(Config{Username: "ad|min", PasswordHash: string(hash)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	tok := a.issue(now)
	if !a.valid(tok, now.Add(time.Hour)) {
		t.Fatal("token for username with '|' must validate")
	}
	if a.valid(tok, now.Add(sessionTTL+time.Minute)) {
		t.Fatal("expired token must be rejected")
	}

	// A token minted for a different user must not validate against this authenticator.
	other, _ := newAuthenticator(Config{Username: "ad", PasswordHash: string(hash)})
	if a.valid(other.issue(now), now.Add(time.Hour)) {
		t.Fatal("token from a different signing key/user must be rejected")
	}
}
