package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// sessionCookie holds the authenticated session token after a successful login.
const sessionCookie = "nsg_session"

// sessionTTL is how long a login lasts before re-authentication is required.
const sessionTTL = 12 * time.Hour

// authenticator verifies credentials and issues/validates session cookies. The session
// is a self-contained HMAC-signed token (expiry|username) so the server holds no
// session table — restart simply invalidates all sessions, which is acceptable for a
// local instrument.
type authenticator struct {
	username     string
	passwordHash string
	signingKey   []byte // random per-process; rotating it on restart logs everyone out
}

// newAuthenticator builds an authenticator from config. A fresh random signing key is
// generated per process so session cookies cannot be forged and do not survive a
// restart.
func newAuthenticator(cfg Config) (*authenticator, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("web: generate session key: %w", err)
	}
	return &authenticator{
		username:     cfg.Username,
		passwordHash: cfg.PasswordHash,
		signingKey:   key,
	}, nil
}

// configured reports whether credentials are set. With no username or hash the
// dashboard refuses every login rather than allowing anonymous access.
func (a *authenticator) configured() bool {
	return a.username != "" && a.passwordHash != ""
}

// verify checks a username/password pair. The username is compared in constant time to
// avoid leaking its length/content via timing, and the password is checked with bcrypt.
// A bcrypt compare always runs (even on username mismatch) to keep timing uniform.
func (a *authenticator) verify(username, password string) bool {
	if !a.configured() {
		// Still spend time on bcrypt to avoid a timing oracle for "not configured".
		_ = bcrypt.CompareHashAndPassword([]byte(a.passwordHash), []byte(password))
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.username)) == 1
	passErr := bcrypt.CompareHashAndPassword([]byte(a.passwordHash), []byte(password))
	return userOK && passErr == nil
}

// issue creates a signed session token valid until now+sessionTTL.
//
// The username is base64url-encoded inside the payload so that a username containing
// the '|' delimiter cannot corrupt the field layout (all three fields — decimal
// expiry, base64 username, base64 signature — are then '|'-free).
func (a *authenticator) issue(now time.Time) string {
	exp := now.Add(sessionTTL).Unix()
	uEnc := base64.RawURLEncoding.EncodeToString([]byte(a.username))
	payload := strconv.FormatInt(exp, 10) + "|" + uEnc
	sig := a.sign(payload)
	raw := payload + "|" + sig
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// valid reports whether a session token is well-formed, correctly signed, for the
// configured user, and unexpired.
func (a *authenticator) valid(token string, now time.Time) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return false
	}
	exp, uEnc, sig := parts[0], parts[1], parts[2]
	expected := a.sign(exp + "|" + uEnc)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
		return false
	}
	user, err := base64.RawURLEncoding.DecodeString(uEnc)
	if err != nil {
		return false
	}
	if subtle.ConstantTimeCompare(user, []byte(a.username)) != 1 {
		return false
	}
	ts, err := strconv.ParseInt(exp, 10, 64)
	if err != nil {
		return false
	}
	return now.Unix() < ts
}

func (a *authenticator) sign(payload string) string {
	mac := hmac.New(sha256.New, a.signingKey)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// authedFromRequest returns true if the request carries a valid session cookie.
func (a *authenticator) authedFromRequest(r *http.Request, now time.Time) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	return a.valid(c.Value, now)
}

// setSession writes the session cookie on a successful login.
func setSession(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(sessionTTL),
	})
}

// clearSession expires the session cookie on logout.
func clearSession(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
