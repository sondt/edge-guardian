package web

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Login throttle: cap failed attempts per client IP within a sliding window to blunt
// credential-guessing. Kept dependency-free (no x/time/rate) — a small mutex-guarded
// map is enough for a local dashboard.
const (
	loginMaxAttempts = 5
	loginWindow      = 1 * time.Minute
)

// loginLimiter counts recent login attempts per key (client IP).
type loginLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{hits: make(map[string][]time.Time), max: max, window: window}
}

// allow records an attempt for key at now and reports whether it is within the cap.
// Returns false once the key has reached max attempts inside the window.
func (l *loginLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := now.Add(-l.window)
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

// reset clears a key after a successful login so legitimate users are not throttled.
func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.hits, key)
	l.mu.Unlock()
}

// clientIP extracts the remote IP from the request (no proxy header trust — the
// dashboard binds loopback and sits behind a trusted reverse proxy if exposed).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
