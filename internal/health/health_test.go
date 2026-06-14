package health

import (
	"sync"
	"testing"
	"time"
)

// fixedClock returns a controllable clock starting at a stable minute boundary.
func fixedClock(start time.Time) (*time.Time, func() time.Time) {
	cur := start
	return &cur, func() time.Time { return cur }
}

var base = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

func TestHealth_ObserveSnapshotRatios(t *testing.T) {
	cur, now := fixedClock(base)
	h := New(Config{WindowMins: 10, Now: now})

	// 7×2xx, 1×3xx, 1×4xx, 1×5xx for site a.
	for i := 0; i < 7; i++ {
		h.Observe("a", 200, 0.05, 100, false, *cur)
	}
	h.Observe("a", 301, 0.05, 100, false, *cur)
	h.Observe("a", 404, 0.05, 100, false, *cur)
	h.Observe("a", 500, 0.05, 100, false, *cur)

	st, ok := h.Snapshot("a", 10)
	if !ok {
		t.Fatal("snapshot missing")
	}
	if st.Reqs != 10 {
		t.Fatalf("reqs=%d want 10", st.Reqs)
	}
	if st.Status2xx != 7 || st.Status3xx != 1 || st.Status4xx != 1 || st.Status5xx != 1 {
		t.Fatalf("status mix wrong: %+v", st)
	}
	if !approx(st.Err5xxRatio, 0.1, 1e-9) {
		t.Fatalf("err5xx ratio=%v want 0.1", st.Err5xxRatio)
	}
	// 10 reqs over 10 min = 600s → ~0.0167 req/s.
	if !approx(st.ReqPerSec, 10.0/600.0, 1e-9) {
		t.Fatalf("req/s=%v", st.ReqPerSec)
	}
	if !st.HasLatency {
		t.Fatal("should have latency")
	}
}

func TestHealth_UnknownSite(t *testing.T) {
	_, now := fixedClock(base)
	h := New(Config{WindowMins: 10, Now: now})
	if _, ok := h.Snapshot("nope", 10); ok {
		t.Fatal("unknown site should return ok=false")
	}
}

func TestHealth_SitesAllowlist(t *testing.T) {
	cur, now := fixedClock(base)
	h := New(Config{WindowMins: 10, Sites: []string{"keep.com"}, Now: now})
	h.Observe("keep.com", 200, 0, 0, false, *cur)
	h.Observe("drop.com", 200, 0, 0, false, *cur)

	if _, ok := h.Snapshot("keep.com", 10); !ok {
		t.Fatal("allowlisted site must be tracked")
	}
	if _, ok := h.Snapshot("drop.com", 10); ok {
		t.Fatal("non-allowlisted site must be dropped")
	}
}

func TestHealth_EmptyHostBucketsAll(t *testing.T) {
	cur, now := fixedClock(base)
	h := New(Config{WindowMins: 10, Now: now})
	h.Observe("", 200, 0, 0, false, *cur)
	if _, ok := h.Snapshot("all", 10); !ok {
		t.Fatal("empty host should bucket under 'all'")
	}
}

func TestHealth_WindowExpiry(t *testing.T) {
	cur, now := fixedClock(base)
	h := New(Config{WindowMins: 5, Now: now})

	// 3 reqs now.
	for i := 0; i < 3; i++ {
		h.Observe("a", 200, 0, 0, false, *cur)
	}
	// Advance 10 minutes (beyond the 5-min window) and observe 1 req.
	*cur = base.Add(10 * time.Minute)
	h.Observe("a", 200, 0, 0, false, *cur)

	st, _ := h.Snapshot("a", 5)
	if st.Reqs != 1 {
		t.Fatalf("reqs=%d want 1 (old 3 expired out of window)", st.Reqs)
	}
}

func TestHealth_Classify(t *testing.T) {
	cur, now := fixedClock(base)
	th := Thresholds{Err5xxRatio: 0.05, P95Sec: 2.0}
	h := New(Config{WindowMins: 10, Thresholds: th, Now: now})

	// Healthy: all 2xx, fast.
	for i := 0; i < 20; i++ {
		h.Observe("ok.com", 200, 0.1, 0, false, *cur)
	}
	st, _ := h.Snapshot("ok.com", 10)
	if st.Status != "Healthy" {
		t.Fatalf("status=%q want Healthy", st.Status)
	}

	// Degraded: high 5xx.
	for i := 0; i < 10; i++ {
		h.Observe("bad.com", 500, 0.1, 0, false, *cur)
	}
	for i := 0; i < 10; i++ {
		h.Observe("bad.com", 200, 0.1, 0, false, *cur)
	}
	st, _ = h.Snapshot("bad.com", 10)
	if st.Status != "Degraded" {
		t.Fatalf("status=%q want Degraded (50%% 5xx)", st.Status)
	}
}

func TestHealth_DownAndIdle(t *testing.T) {
	cur, now := fixedClock(base)
	h := New(Config{WindowMins: 10, Now: now})

	// Idle: never seen → unknown, but a site with zero in-window reqs reads Idle.
	// Build traffic at base, then jump ahead 5 min so recent (last 2 min) is empty but
	// the window (10 min) still holds the earlier traffic → "Down".
	for i := 0; i < 30; i++ {
		h.Observe("site.com", 200, 0, 0, false, *cur)
	}
	*cur = base.Add(5 * time.Minute)
	st, _ := h.Snapshot("site.com", 10)
	if st.Status != "Down" {
		t.Fatalf("status=%q want Down (traffic stopped)", st.Status)
	}

	// Jump far beyond the window → no reqs in window → Idle.
	*cur = base.Add(60 * time.Minute)
	st, _ = h.Snapshot("site.com", 10)
	if st.Status != "Idle" {
		t.Fatalf("status=%q want Idle (no traffic in window)", st.Status)
	}
}

func TestHealth_Prune(t *testing.T) {
	cur, now := fixedClock(base)
	h := New(Config{WindowMins: 5, Now: now})
	h.Observe("gone.com", 200, 0, 0, false, *cur)

	*cur = base.Add(60 * time.Minute)
	h.Prune()
	if _, ok := h.Snapshot("gone.com", 5); ok {
		t.Fatal("site with no in-window data should be pruned")
	}
}

func TestHealth_ConcurrentObserve(t *testing.T) {
	cur, now := fixedClock(base)
	h := New(Config{WindowMins: 10, Now: now})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				h.Observe("a", 200, 0.01, 10, false, *cur)
			}
		}()
	}
	wg.Wait()
	st, _ := h.Snapshot("a", 10)
	if st.Reqs != 8000 {
		t.Fatalf("reqs=%d want 8000", st.Reqs)
	}
}

func TestHealth_SnapshotAll(t *testing.T) {
	cur, now := fixedClock(base)
	h := New(Config{WindowMins: 10, Now: now})
	h.Observe("b.com", 200, 0, 0, false, *cur)
	h.Observe("a.com", 200, 0, 0, false, *cur)
	all := h.SnapshotAll(10)
	if len(all) != 2 {
		t.Fatalf("snapshotall len=%d want 2", len(all))
	}
	if all[0].Host != "a.com" || all[1].Host != "b.com" {
		t.Fatalf("not sorted by host: %v", all)
	}
}

func TestHealth_UpstreamErr(t *testing.T) {
	cur, now := fixedClock(base)
	h := New(Config{WindowMins: 10, Now: now})
	h.Observe("a", 502, 0, 0, true, *cur)
	h.Observe("a", 503, 0, 0, true, *cur)
	h.Observe("a", 200, 0, 0, false, *cur)
	st, _ := h.Snapshot("a", 10)
	if st.UpstreamErr != 2 {
		t.Fatalf("upstreamErr=%d want 2", st.UpstreamErr)
	}
}
