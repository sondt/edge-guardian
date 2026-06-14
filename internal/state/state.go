// Package state lưu trạng thái ban ra file JSON: dedup thông báo và khôi phục
// nftables sau reboot. Ghi atomic (file tạm + rename) để tránh hỏng khi crash.
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

// Entry mô tả một IP từng/đang bị ban.
type Entry struct {
	IP        string    `json:"ip"`
	Detector  string    `json:"detector"` // nguồn phát hiện: "http" | "sshd" | ...
	Reason    string    `json:"reason"`   // lý do (vd path scanner, hoặc "failed SSH login")
	FirstSeen time.Time `json:"first_seen"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Hits      int       `json:"hits"`
	BanCount  int       `json:"ban_count"`
}

// active báo entry còn hiệu lực tại thời điểm now.
func (e Entry) active(now time.Time) bool {
	return e.ExpiresAt.After(now)
}

// remembered báo entry còn nên giữ lại tại now: đang active, HOẶC đã hết hạn nhưng
// còn trong "memory window" (giữ lịch sử offender để ban leo thang). memory=0 → chỉ
// giữ entry còn active (hành vi cũ).
func (e Entry) remembered(now time.Time, memory time.Duration) bool {
	return e.ExpiresAt.Add(memory).After(now)
}

// Store giữ tập entry trong bộ nhớ, đồng bộ với file JSON trên đĩa.
type Store struct {
	path string

	mu      sync.Mutex
	entries map[string]Entry
}

// Load đọc state từ path. File thiếu => store rỗng (không phải lỗi).
// Các entry đã hết hạn tại now bị prune ngay khi nạp.
// Load đọc state từ path. memory là khoảng giữ lịch sử offender đã hết hạn (cho ban
// leo thang); memory=0 → chỉ giữ entry còn active (prune entry hết hạn ngay khi nạp).
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

// Get trả về (copy của) entry theo IP.
func (s *Store) Get(ip string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[ip]
	return e, ok
}

// IsBanned cho biết IP đang bị ban (còn hạn) tại now.
func (s *Store) IsBanned(ip string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[ip]
	return ok && e.active(now)
}

// RecordHit tăng counter hit cho một IP đã bị ban (không tạo entry mới).
func (s *Store) RecordHit(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[ip]; ok {
		e.Hits++
		s.entries[ip] = e
	}
}

// Ban ghi/cập nhật một entry ban. Trả về entry kết quả (bất biến với caller).
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

// Remove xóa một IP khỏi state. Trả về true nếu có tồn tại.
func (s *Store) Remove(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.entries[ip]
	delete(s.entries, ip)
	return ok
}

// Prune xóa khỏi bộ nhớ mọi entry đã hết hạn tại now. Trả về số entry đã xóa.
// Gọi định kỳ để map/state file không phình theo lưu lượng quét.
// Prune xóa các entry không còn nên giữ tại now (hết hạn VÀ quá memory window).
// memory=0 → xóa mọi entry đã hết hạn. Trả về số entry đã xóa.
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

// Active trả về danh sách entry còn hạn tại now, sắp xếp theo IP (ổn định).
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

// Save ghi toàn bộ entry ra đĩa theo cơ chế atomic (tmp + rename).
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
	defer os.Remove(tmpName) // no-op nếu rename thành công

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
