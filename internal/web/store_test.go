package web

import (
	"testing"
	"time"
)

// fixedClock returns a deterministic now() for tests.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestNewStoreClampsRetention(t *testing.T) {
	s := NewStore(0)
	if s.retention != 24*time.Hour {
		t.Fatalf("zero retention should clamp to 24h, got %v", s.retention)
	}
	s2 := NewStore(-time.Hour)
	if s2.retention != 24*time.Hour {
		t.Fatalf("negative retention should clamp to 24h, got %v", s2.retention)
	}
}

func TestPushAssignsTimestampWhenZero(t *testing.T) {
	now := time.Date(2026, 6, 14, 9, 0, 0, 0, time.UTC)
	s := NewStore(time.Hour)
	s.now = fixedClock(now)
	s.Push(Event{IP: "1.1.1.1", Detector: "http", Action: "banned"})
	rec := s.Recent(1)
	if len(rec) != 1 {
		t.Fatalf("want 1 event, got %d", len(rec))
	}
	if !rec[0].At.Equal(now) {
		t.Fatalf("zero At should default to now; got %v want %v", rec[0].At, now)
	}
}

func TestTrimDropsExpiredEvents(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	s := NewStore(time.Hour)
	s.now = fixedClock(now)
	// Old event (2h ago) should be trimmed; recent one retained.
	s.Push(Event{At: now.Add(-2 * time.Hour), IP: "old", Action: "banned"})
	s.Push(Event{At: now.Add(-10 * time.Minute), IP: "new", Action: "banned"})
	rec := s.Recent(10)
	if len(rec) != 1 {
		t.Fatalf("want 1 retained event, got %d", len(rec))
	}
	if rec[0].IP != "new" {
		t.Fatalf("retained wrong event: %s", rec[0].IP)
	}
}

func TestRecentNewestFirst(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	s := NewStore(time.Hour)
	s.now = fixedClock(now)
	for i := 0; i < 5; i++ {
		s.Push(Event{At: now.Add(time.Duration(-i) * time.Minute), IP: string(rune('a' + i)), Action: "banned"})
	}
	rec := s.Recent(3)
	if len(rec) != 3 {
		t.Fatalf("want 3, got %d", len(rec))
	}
	// Last pushed (i=4, oldest At) is appended last, so Recent returns it first.
	if rec[0].IP != "e" {
		t.Fatalf("Recent should be newest-appended first; got %s", rec[0].IP)
	}
}

func TestRecentBounds(t *testing.T) {
	s := NewStore(time.Hour)
	if got := s.Recent(0); got != nil {
		t.Fatalf("Recent(0) should be nil, got %v", got)
	}
	if got := s.Recent(-1); got != nil {
		t.Fatalf("Recent(-1) should be nil, got %v", got)
	}
	if got := s.Recent(5); len(got) != 0 {
		t.Fatalf("Recent on empty store should be empty, got %d", len(got))
	}
}

func TestSnapshotCountsAndState(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	s := NewStore(2 * time.Hour)
	s.now = fixedClock(now)

	// 3 banned http from CN/AS4837, 1 would-ban portscan from RU/AS1299, all recent.
	for i := 0; i < 3; i++ {
		s.Push(Event{At: now.Add(-time.Duration(i) * time.Minute), IP: "1.1.1.1", Detector: "http", Action: "banned", Country: "CN", ASN: "AS4837"})
	}
	s.Push(Event{At: now.Add(-time.Minute), IP: "2.2.2.2", Detector: "portscan", Action: "would-ban", Country: "RU", ASN: "AS1299"})

	m := s.Snapshot()
	if m.TotalEvents != 4 {
		t.Fatalf("TotalEvents = %d, want 4", m.TotalEvents)
	}
	if m.Banned != 3 {
		t.Fatalf("Banned = %d, want 3", m.Banned)
	}
	if m.WouldBan != 1 {
		t.Fatalf("WouldBan = %d, want 1", m.WouldBan)
	}
	// Top origin should be CN·AS4837 with 3 hits.
	if len(m.TopOrigins) == 0 || m.TopOrigins[0].Hits != 3 {
		t.Fatalf("top origin wrong: %+v", m.TopOrigins)
	}
	if m.TopOrigins[0].Label != "CN · AS4837" {
		t.Fatalf("top origin label = %q", m.TopOrigins[0].Label)
	}
	// Detector ranking: http (3) before portscan (1).
	if len(m.Detectors) < 2 || m.Detectors[0].Name != "http" {
		t.Fatalf("detector ranking wrong: %+v", m.Detectors)
	}
}

func TestSnapshotUnderScan(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	s := NewStore(time.Hour)
	s.now = fixedClock(now)
	// Pile many events into the same recent instant to push a bucket over threshold.
	for i := 0; i < scanThreshold+2; i++ {
		s.Push(Event{At: now.Add(-time.Second), IP: "9.9.9.9", Detector: "portscan", Action: "banned"})
	}
	m := s.Snapshot()
	if !m.UnderAtk || m.State != "Under scan" {
		t.Fatalf("expected Under scan, got state=%q underAtk=%v peak=%v", m.State, m.UnderAtk, m.PeakWin)
	}
}

func TestSnapshotQuietWhenEmpty(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	s := NewStore(time.Hour)
	s.now = fixedClock(now)
	m := s.Snapshot()
	if m.State != "Quiet" || m.UnderAtk {
		t.Fatalf("empty store should be Quiet, got %q underAtk=%v", m.State, m.UnderAtk)
	}
	if len(m.Sentinel) != SentinelBuckets {
		t.Fatalf("sentinel buckets = %d, want %d", len(m.Sentinel), SentinelBuckets)
	}
	if len(m.EventsSpark) != SparkBuckets {
		t.Fatalf("spark buckets = %d, want %d", len(m.EventsSpark), SparkBuckets)
	}
}

func TestSentinelHollowForWouldBanOnly(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	s := NewStore(time.Hour)
	s.now = fixedClock(now)
	s.Push(Event{At: now.Add(-time.Second), IP: "5.5.5.5", Detector: "http", Action: "would-ban"})
	m := s.Snapshot()
	found := false
	for _, tk := range m.Sentinel {
		if tk.Count > 0 {
			found = true
			if !tk.Hollow {
				t.Fatalf("would-ban-only bucket should be hollow")
			}
		}
	}
	if !found {
		t.Fatal("expected at least one populated sentinel tick")
	}
}

func TestConcurrentPushSnapshot(t *testing.T) {
	s := NewStore(time.Hour)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			s.Push(Event{IP: "1.1.1.1", Detector: "http", Action: "banned"})
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		_ = s.Snapshot()
		_ = s.Recent(10)
	}
	<-done
}
