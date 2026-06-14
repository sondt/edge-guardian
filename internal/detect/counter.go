package detect

import (
	"sync"
	"time"
)

// Counter counts "signals" per key (IP) within a sliding window and reports when the threshold
// is exceeded. The sub parameter is an optional sub-key: the distinct counter (port scan) counts
// DIFFERENT subs, while the plain hit counter ignores sub.
type Counter interface {
	Record(key, sub string, now time.Time) (count int, tripped bool)
	Forget(key string)
	Prune(now time.Time)
}

// hits is a Window-based Counter (counts records), ignoring sub. Used for HTTP/SSH/honeypot.
type hits struct{ w *Window }

// Hits creates a Counter that counts events within the window (threshold by hit count).
func Hits(threshold int, window time.Duration) Counter {
	return &hits{w: NewWindow(threshold, window)}
}

func (h *hits) Record(key, _ string, now time.Time) (int, bool) { return h.w.Record(key, now) }
func (h *hits) Forget(key string)                               { h.w.Forget(key) }
func (h *hits) Prune(now time.Time)                             { h.w.Prune(now) }

// Distinct is a Counter that counts the number of DIFFERENT subs of a key within the window —
// used for port scan (counts distinct destination PORTs an IP touches, not the total packet
// count). Hitting one port many times does not increase the count; touching many different ports
// is what counts as a scan.
type Distinct struct {
	threshold int
	window    time.Duration

	mu   sync.Mutex
	seen map[string]map[string]time.Time // key -> (sub -> last touch)
}

// NewDistinct creates a distinct counter with a sub-count threshold and window width.
func NewDistinct(threshold int, window time.Duration) *Distinct {
	if threshold < 1 {
		threshold = 1
	}
	return &Distinct{threshold: threshold, window: window, seen: make(map[string]map[string]time.Time)}
}

// Record records key touching sub at now, prunes subs older than the window, and returns
// (number of distinct subs still in the window, whether the threshold is reached).
func (d *Distinct) Record(key, sub string, now time.Time) (int, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	subs := d.seen[key]
	if subs == nil {
		subs = make(map[string]time.Time)
		d.seen[key] = subs
	}
	subs[sub] = now

	cutoff := now.Add(-d.window)
	count := 0
	for s, t := range subs {
		if t.After(cutoff) {
			count++
		} else {
			delete(subs, s)
		}
	}
	return count, count >= d.threshold
}

// Forget clears a key's history (called after a ban).
func (d *Distinct) Forget(key string) {
	d.mu.Lock()
	delete(d.seen, key)
	d.mu.Unlock()
}

// Prune removes keys with no subs left in the window as of now.
func (d *Distinct) Prune(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := now.Add(-d.window)
	for key, subs := range d.seen {
		for s, t := range subs {
			if !t.After(cutoff) {
				delete(subs, s)
			}
		}
		if len(subs) == 0 {
			delete(d.seen, key)
		}
	}
}
