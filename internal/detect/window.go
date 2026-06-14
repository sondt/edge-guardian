package detect

import (
	"sync"
	"time"
)

// Window counts matches per key (IP) within a sliding window.
// Safe for concurrent access.
type Window struct {
	threshold int
	window    time.Duration

	mu   sync.Mutex
	hits map[string][]time.Time
}

// NewWindow creates a sliding window with the given threshold and width.
func NewWindow(threshold int, window time.Duration) *Window {
	if threshold < 1 {
		threshold = 1
	}
	return &Window{
		threshold: threshold,
		window:    window,
		hits:      make(map[string][]time.Time),
	}
}

// Record records a match for key at now, prunes timestamps older than the window,
// and returns (count still in the window, whether the threshold is reached).
func (w *Window) Record(key string, now time.Time) (count int, tripped bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	cutoff := now.Add(-w.window)
	prev := w.hits[key]
	kept := prev[:0]
	for _, t := range prev {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	w.hits[key] = kept

	return len(kept), len(kept) >= w.threshold
}

// Forget clears a key's history (called after a ban to free memory).
func (w *Window) Forget(key string) {
	w.mu.Lock()
	delete(w.hits, key)
	w.mu.Unlock()
}

// Prune removes every key with no timestamps left in the window as of now.
// Call periodically to keep the map from growing over time.
func (w *Window) Prune(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()

	cutoff := now.Add(-w.window)
	for key, ts := range w.hits {
		kept := ts[:0]
		for _, t := range ts {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(w.hits, key)
		} else {
			w.hits[key] = kept
		}
	}
}
