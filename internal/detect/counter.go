package detect

import (
	"sync"
	"time"
)

// Counter đếm "tín hiệu" theo từng khóa (IP) trong cửa sổ trượt và báo khi vượt ngưỡng.
// Tham số sub là khóa con tùy chọn: bộ đếm distinct (port scan) đếm số sub KHÁC NHAU,
// còn bộ đếm hit thường bỏ qua sub.
type Counter interface {
	Record(key, sub string, now time.Time) (count int, tripped bool)
	Forget(key string)
	Prune(now time.Time)
}

// hits là Counter dựa trên Window (đếm số lần ghi), bỏ qua sub. Dùng cho HTTP/SSH/honeypot.
type hits struct{ w *Window }

// Hits tạo Counter đếm số sự kiện trong cửa sổ (ngưỡng theo số hit).
func Hits(threshold int, window time.Duration) Counter {
	return &hits{w: NewWindow(threshold, window)}
}

func (h *hits) Record(key, _ string, now time.Time) (int, bool) { return h.w.Record(key, now) }
func (h *hits) Forget(key string)                               { h.w.Forget(key) }
func (h *hits) Prune(now time.Time)                             { h.w.Prune(now) }

// Distinct là Counter đếm số sub KHÁC NHAU của một key trong cửa sổ — dùng cho port
// scan (đếm số PORT đích distinct mà một IP chạm tới, không phải tổng số gói). Gõ nhầm
// một port nhiều lần không làm tăng đếm; chạm nhiều port khác nhau mới tính là scan.
type Distinct struct {
	threshold int
	window    time.Duration

	mu   sync.Mutex
	seen map[string]map[string]time.Time // key -> (sub -> lần chạm gần nhất)
}

// NewDistinct tạo bộ đếm distinct với ngưỡng số sub và độ rộng cửa sổ.
func NewDistinct(threshold int, window time.Duration) *Distinct {
	if threshold < 1 {
		threshold = 1
	}
	return &Distinct{threshold: threshold, window: window, seen: make(map[string]map[string]time.Time)}
}

// Record ghi nhận key chạm sub tại now, dọn sub cũ hơn cửa sổ, trả về (số sub distinct
// còn trong cửa sổ, đã đạt ngưỡng chưa).
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

// Forget xóa lịch sử của một key (gọi sau khi đã ban).
func (d *Distinct) Forget(key string) {
	d.mu.Lock()
	delete(d.seen, key)
	d.mu.Unlock()
}

// Prune dọn các key không còn sub nào trong cửa sổ tính tới now.
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
