package state

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_MissingFileIsEmpty(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "nope.json"), time.Now(), 0)
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if len(s.Active(time.Now())) != 0 {
		t.Fatal("expected empty store")
	}
}

func TestStore_BanAndPersist(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "state.json")

	s, err := Load(path, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	e := s.Ban("1.2.3.4", "http", "/wp-login.php", 1, now, now.Add(time.Hour))
	if e.BanCount != 1 || e.Hits != 1 {
		t.Fatalf("entry=%+v want BanCount=1 Hits=1", e)
	}
	if !s.IsBanned("1.2.3.4", now) {
		t.Fatal("should be banned")
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	// Reload from disk preserves the active entry.
	s2, err := Load(path, now.Add(time.Minute), 0)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get("1.2.3.4")
	if !ok || got.Reason != "/wp-login.php" {
		t.Fatalf("reloaded entry=%+v ok=%v", got, ok)
	}
}

func TestLoad_PrunesExpired(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "state.json")

	s, _ := Load(path, now, 0)
	s.Ban("1.1.1.1", "http", "/a", 1, now, now.Add(time.Hour))   // active
	s.Ban("2.2.2.2", "http", "/b", 1, now, now.Add(time.Minute)) // expires sooner
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	// Reload 30 minutes later: only 1.1.1.1 survives.
	s2, _ := Load(path, now.Add(30*time.Minute), 0)
	if s2.IsBanned("2.2.2.2", now.Add(30*time.Minute)) {
		t.Fatal("expired entry should be pruned on load")
	}
	if !s2.IsBanned("1.1.1.1", now.Add(30*time.Minute)) {
		t.Fatal("active entry should survive")
	}
}

func TestStore_RecordHitAndBanCountEscalates(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	s, _ := Load(filepath.Join(t.TempDir(), "s.json"), now, 0)

	s.Ban("9.9.9.9", "http", "/x", 1, now, now.Add(time.Hour))
	s.RecordHit("9.9.9.9")
	s.RecordHit("9.9.9.9")
	got, _ := s.Get("9.9.9.9")
	if got.Hits != 3 {
		t.Fatalf("Hits=%d want 3", got.Hits)
	}

	// Re-ban (repeat offender) increments BanCount.
	e := s.Ban("9.9.9.9", "http", "/y", 0, now.Add(2*time.Hour), now.Add(3*time.Hour))
	if e.BanCount != 2 {
		t.Fatalf("BanCount=%d want 2", e.BanCount)
	}
	if e.FirstSeen != now {
		t.Fatalf("FirstSeen should be preserved, got %v", e.FirstSeen)
	}
}

func TestStore_Remove(t *testing.T) {
	now := time.Now()
	s, _ := Load(filepath.Join(t.TempDir(), "s.json"), now, 0)
	s.Ban("5.5.5.5", "http", "/z", 1, now, now.Add(time.Hour))

	if !s.Remove("5.5.5.5") {
		t.Fatal("Remove should report existing entry")
	}
	if s.Remove("5.5.5.5") {
		t.Fatal("second Remove should report false")
	}
	if s.IsBanned("5.5.5.5", now) {
		t.Fatal("removed entry should not be banned")
	}
}

func TestStore_Prune(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	s, _ := Load(filepath.Join(t.TempDir(), "s.json"), now, 0)
	s.Ban("1.1.1.1", "http", "/a", 1, now, now.Add(time.Hour))   // active
	s.Ban("2.2.2.2", "http", "/b", 1, now, now.Add(time.Minute)) // expires sooner

	removed := s.Prune(now.Add(30*time.Minute), 0)
	if removed != 1 {
		t.Fatalf("Prune removed=%d want 1", removed)
	}
	if s.IsBanned("2.2.2.2", now.Add(30*time.Minute)) {
		t.Fatal("expired entry should be pruned")
	}
	if !s.IsBanned("1.1.1.1", now.Add(30*time.Minute)) {
		t.Fatal("active entry must survive prune")
	}
}

func TestStore_Active_ReturnsCopies(t *testing.T) {
	now := time.Now()
	s, _ := Load(filepath.Join(t.TempDir(), "s.json"), now, 0)
	s.Ban("7.7.7.7", "http", "/q", 1, now, now.Add(time.Hour))

	active := s.Active(now)
	active[0].Hits = 999 // mutate the returned copy

	got, _ := s.Get("7.7.7.7")
	if got.Hits == 999 {
		t.Fatal("Active() must return copies, not aliases into the store")
	}
}
