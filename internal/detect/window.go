package detect

import (
	"sync"
	"time"
)

// Window đếm số lần khớp theo từng khóa (IP) trong một cửa sổ trượt.
// An toàn cho truy cập đồng thời.
type Window struct {
	threshold int
	window    time.Duration

	mu   sync.Mutex
	hits map[string][]time.Time
}

// NewWindow tạo cửa sổ trượt với ngưỡng và độ rộng cho trước.
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

// Record ghi một lần khớp cho key tại thời điểm now, dọn các mốc cũ hơn cửa sổ,
// và trả về (số lần còn trong cửa sổ, đã đạt ngưỡng chưa).
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

// Forget xóa lịch sử của một key (gọi sau khi đã ban để giải phóng bộ nhớ).
func (w *Window) Forget(key string) {
	w.mu.Lock()
	delete(w.hits, key)
	w.mu.Unlock()
}

// Prune dọn toàn bộ key không còn mốc nào trong cửa sổ tính tới now.
// Gọi định kỳ để tránh map phình theo thời gian.
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
