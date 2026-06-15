package web

import (
	"sync"
	"time"
)

// SentinelBuckets is the number of vertical ticks rendered on the Sentinel line.
// One bucket roughly maps to a short slice of recent time so the line reads like a
// seismograph of the server's exposure.
const SentinelBuckets = 72

// SparkBuckets is the number of points in a readout-card sparkline (24h view).
const SparkBuckets = 24

// FeedDefault is how many recent events the feed shows by default.
const FeedDefault = 12

// Store is the in-RAM event ring buffer plus metrics aggregator. It lives for the
// configured retention window (~24h) and is lost on restart — acceptable for the MVP.
// All access is guarded by a single RWMutex; Push takes the write lock, reads take
// the read lock. The slice is trimmed lazily on every Push so memory stays bounded by
// the event rate within the retention window.
type Store struct {
	mu        sync.RWMutex
	events    []Event
	retention time.Duration
	now       func() time.Time // injectable clock for deterministic tests
}

// NewStore creates an empty Store retaining events for the given window. A zero or
// negative retention is clamped to 24h so the buffer always has a sane bound.
func NewStore(retention time.Duration) *Store {
	if retention <= 0 {
		retention = 24 * time.Hour
	}
	return &Store{
		events:    make([]Event, 0, 256),
		retention: retention,
		now:       time.Now,
	}
}

// Push records a detection event. Out-of-retention events are dropped on the next
// trim. The stored event is a copy, so the caller may reuse its Event value freely.
func (s *Store) Push(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.At.IsZero() {
		e.At = s.now()
	}
	s.events = append(s.events, e)
	s.trimLocked(s.now())
}

// Recent returns up to n most-recent events, newest first. It never returns more
// events than are retained. The returned slice is a fresh copy safe to read without
// the lock.
func (s *Store) Recent(n int) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n <= 0 {
		return nil
	}
	total := len(s.events)
	if n > total {
		n = total
	}
	out := make([]Event, 0, n)
	for i := total - 1; i >= total-n; i-- {
		out = append(out, s.events[i])
	}
	return out
}

// Snapshot aggregates the retained events into a Metrics value precomputed for the UI.
// It is the single read path the handlers use to render the sentinel, readouts, and
// origin ranking.
func (s *Store) Snapshot() Metrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()
	return aggregate(s.events, now, s.retention)
}

// trimLocked drops events older than the retention window. Caller holds the write lock.
// Because events are appended in time order, the cut point is the first in-window event.
func (s *Store) trimLocked(now time.Time) {
	cutoff := now.Add(-s.retention)
	idx := 0
	for idx < len(s.events) && s.events[idx].At.Before(cutoff) {
		idx++
	}
	if idx == 0 {
		return
	}
	// Compact in place to release the head without reallocating on every push.
	remaining := len(s.events) - idx
	copy(s.events, s.events[idx:])
	s.events = s.events[:remaining]
}

// SentinelTick is one vertical mark on the Sentinel line.
type SentinelTick struct {
	Severity  float64 // 0..1 → tick height
	Intensity float64 // 0..1 → opacity of the alert color
	Hollow    bool    // true for dry-run "would-ban" (outline tick)
	Count     int     // events folded into this bucket (for the title tooltip)
}

// OriginRow is one row of the "top origin" ranking (country + ASN).
type OriginRow struct {
	Label string  // human label, e.g. "CN · AS4837" or "Unknown"
	Hits  int     // events attributed to this origin
	Share float64 // fraction of total events, 0..1
}

// DetectorRow is one detector's share of recent activity.
type DetectorRow struct {
	Name  string
	Hits  int
	Share float64 // 0..1
}

// Metrics holds precomputed aggregates for the UI. Every field is plain data the
// templates read directly — no further computation happens during rendering.
type Metrics struct {
	GeneratedAt time.Time

	TotalEvents int // events within the retention window
	Banned      int // events with Action == "banned"
	WouldBan    int // events with Action == "would-ban"
	Active      int // IPs currently in the ledger (set by the handler from DataSource;
	//                matches the /bans tab — in dry-run these are would-be bans)

	// State is the headline status: "Quiet" or "Under scan".
	State    string
	UnderAtk bool

	Sentinel []SentinelTick // SentinelBuckets entries, oldest→newest
	PeakWin  float64        // peak per-bucket count, for sentinel scaling hints

	EventsSpark []int // SparkBuckets per-hour counts, oldest→newest
	BannedSpark []int // SparkBuckets per-hour banned counts, oldest→newest

	TopOrigins []OriginRow   // ranked, highest first (capped)
	Detectors  []DetectorRow // ranked, highest first

	// PeriodKey is the URL query value for the selected time window ("1h", "24h", "7d", "30d").
	// PeriodLabel is the short display string used in readout card labels.
	PeriodKey   string
	PeriodLabel string
}
