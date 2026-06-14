// Package state persists ban state to a JSON file: notification dedup and nftables
// restore after reboot. Writes are atomic (temp file + rename) to avoid corruption on crash.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Entry describes an IP that was/is banned.
type Entry struct {
	IP        string    `json:"ip"`
	Detector  string    `json:"detector"` // detection source: "http" | "sshd" | ...
	Reason    string    `json:"reason"`   // reason (e.g. path scanner, or "failed SSH login")
	FirstSeen time.Time `json:"first_seen"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Hits      int       `json:"hits"`
	BanCount  int       `json:"ban_count"`
}

// active reports whether the entry is still in effect at time now.
func (e Entry) active(now time.Time) bool {
	return e.ExpiresAt.After(now)
}

// remembered reports whether the entry should still be kept at now: currently active,
// OR expired but still within the "memory window" (keeping offender history for ban
// escalation). memory=0 → keep only active entries (old behavior).
func (e Entry) remembered(now time.Time, memory time.Duration) bool {
	return e.ExpiresAt.Add(memory).After(now)
}

// Store keeps the set of entries in memory, synced with the JSON file on disk.
type Store struct {
	path string

	mu      sync.Mutex
	entries map[string]Entry
}

// Load reads state from path. A missing file => empty store (not an error).
// Entries expired at now are pruned as soon as they are loaded.
// Load reads state from path. memory is the window for keeping expired offender history
// (for ban escalation); memory=0 → keep only active entries (prune expired entries on load).
func Load(path string, now time.Time, memory time.Duration) (*Store, error) {
	s := &Store{path: path, entries: make(map[string]Entry)}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read state %q: %w", path, err)
	}
	if len(data) == 0 {
		return s, nil
	}

	var list []Entry
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse state %q: %w", path, err)
	}
	for _, e := range list {
		if e.remembered(now, memory) {
			s.entries[e.IP] = e
		}
	}
	return s, nil
}

// Get returns a (copy of the) entry by IP.
func (s *Store) Get(ip string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[ip]
	return e, ok
}

// IsBanned reports whether the IP is currently banned (not expired) at now.
func (s *Store) IsBanned(ip string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[ip]
	return ok && e.active(now)
}

// RecordHit increments the hit counter for an already-banned IP (does not create a new entry).
func (s *Store) RecordHit(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[ip]; ok {
		e.Hits++
		s.entries[ip] = e
	}
}

// Ban writes/updates a ban entry. Returns the resulting entry (immutable to the caller).
func (s *Store) Ban(ip, detector, reason string, hits int, now, expires time.Time) Entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[ip]
	if !ok {
		e = Entry{IP: ip, FirstSeen: now}
	}
	e.BannedAt = now
	e.ExpiresAt = expires
	e.Hits += hits
	e.BanCount++
	if detector != "" {
		e.Detector = detector
	}
	if reason != "" {
		e.Reason = reason
	}
	s.entries[ip] = e
	return e
}

// Remove deletes an IP from state. Returns true if it existed.
func (s *Store) Remove(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.entries[ip]
	delete(s.entries, ip)
	return ok
}

// Prune removes from memory every entry expired at now. Returns the number of entries removed.
// Call periodically so the map/state file doesn't grow with scan traffic.
// Prune removes entries that should no longer be kept at now (expired AND past the memory window).
// memory=0 → remove every expired entry. Returns the number of entries removed.
func (s *Store) Prune(now time.Time, memory time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for ip, e := range s.entries {
		if !e.remembered(now, memory) {
			delete(s.entries, ip)
			removed++
		}
	}
	return removed
}

// Active returns the list of entries still valid at now, sorted by IP (stable).
func (s *Store) Active(now time.Time) []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if e.active(now) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// Save writes all entries to disk atomically (tmp + rename).
func (s *Store) Save() error {
	s.mu.Lock()
	list := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		list = append(list, e)
	}
	s.mu.Unlock()

	sort.Slice(list, func(i, j int) bool { return list[i].IP < list[j].IP })

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".state-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp state in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp state: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("rename state into place: %w", err)
	}
	return nil
}
