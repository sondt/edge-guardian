package health

import (
	"sync"
	"time"
)

// maxSites giới hạn số host theo dõi khi không khai báo danh sách `sites` cố định —
// chặn map phình nếu Host trong log bất thường (dù $host thường bị giới hạn bởi
// server_name). Khi đạt trần, host mới bị bỏ qua thay vì cấp phát vô hạn.
const maxSites = 256

// Health giữ rolling counters per-site. Bounded theo (số site × số phút), KHÔNG theo
// volume request. An toàn cho truy cập đồng thời.
type Health struct {
	windowMins int
	allow      map[string]struct{} // danh sách site cố định; rỗng = nhận mọi host
	th         Thresholds
	now        func() time.Time

	mu    sync.Mutex
	sites map[string]*SiteSeries
}

// Config khởi tạo Health.
type Config struct {
	WindowMins int
	Sites      []string // rỗng = theo dõi mọi host gặp trong log
	Thresholds Thresholds
	Now        func() time.Time // nil = time.Now
}

// New tạo Health từ Config.
func New(c Config) *Health {
	if c.WindowMins < 1 {
		c.WindowMins = 180
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	var allow map[string]struct{}
	if len(c.Sites) > 0 {
		allow = make(map[string]struct{}, len(c.Sites))
		for _, s := range c.Sites {
			allow[s] = struct{}{}
		}
	}
	return &Health{
		windowMins: c.WindowMins,
		allow:      allow,
		th:         c.Thresholds,
		now:        now,
		sites:      make(map[string]*SiteSeries),
	}
}

// minuteOf trả về phút Unix của t.
func minuteOf(t time.Time) int64 { return t.Unix() / 60 }

// Observe ghi một quan sát cho host tại thời điểm now. host rỗng → gộp vào "all" (log
// combined không có $host). Site ngoài danh sách `sites` (nếu khai báo) bị bỏ qua.
func (h *Health) Observe(host string, status int, rtSec float64, bytes uint64, upstreamErr bool, now time.Time) {
	if host == "" {
		host = "all"
	}
	if h.allow != nil {
		if _, ok := h.allow[host]; !ok {
			return
		}
	}
	minute := minuteOf(now)

	h.mu.Lock()
	defer h.mu.Unlock()

	s := h.sites[host]
	if s == nil {
		if h.allow == nil && len(h.sites) >= maxSites {
			return // chặn map phình với host bất thường
		}
		s = newSeries(h.windowMins)
		h.sites[host] = s
	}
	s.observe(minute, status, rtSec, bytes, upstreamErr)
}

// Snapshot chụp một site trong cửa sổ windowMins phút (clamp theo cấu hình). Trả về ok
// false nếu site chưa từng thấy.
func (h *Health) Snapshot(host string, windowMins int) (SiteStats, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sites[host]
	if s == nil {
		return SiteStats{}, false
	}
	return h.snapshotLocked(host, s, windowMins), true
}

// SnapshotAll chụp mọi site, sắp theo host.
func (h *Health) SnapshotAll(windowMins int) []SiteStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]SiteStats, 0, len(h.sites))
	for host, s := range h.sites {
		out = append(out, h.snapshotLocked(host, s, windowMins))
	}
	byHost(out)
	return out
}

// snapshotLocked tổng hợp một site (caller giữ mu).
func (h *Health) snapshotLocked(host string, s *SiteSeries, windowMins int) SiteStats {
	if windowMins < 1 || windowMins > h.windowMins {
		windowMins = h.windowMins
	}
	nowMinute := minuteOf(h.now())
	fromMinute := nowMinute - int64(windowMins) + 1

	agg := s.aggregate(fromMinute, nowMinute)
	st := SiteStats{
		Host:        host,
		WindowMins:  windowMins,
		Reqs:        agg.Reqs,
		Status2xx:   agg.Status[2],
		Status3xx:   agg.Status[3],
		Status4xx:   agg.Status[4],
		Status5xx:   agg.Status[5],
		UpstreamErr: agg.UpstreamErr,
		Spark:       s.perMinuteReqs(fromMinute, nowMinute),
	}
	if agg.Reqs > 0 {
		st.ReqPerSec = float64(agg.Reqs) / float64(windowMins*60)
		st.Err5xxRatio = float64(agg.Status[5]) / float64(agg.Reqs)
	}
	if agg.Lat.Count() > 0 {
		st.HasLatency = true
		st.P50Sec = agg.Lat.Quantile(0.50)
		st.P95Sec = agg.Lat.Quantile(0.95)
		st.P99Sec = agg.Lat.Quantile(0.99)
	}

	// recentReqs = số request trong 2 phút gần nhất (để nhận "Down" mà không nhiễu bởi
	// phút hiện tại còn dở).
	recent := s.aggregate(nowMinute-1, nowMinute)
	st.classify(h.th, recent.Reqs)
	return st
}

// Prune dọn các site không còn dữ liệu trong cửa sổ (giải phóng RAM khi một host biến
// mất hẳn). Gọi định kỳ cùng prune detection.
func (h *Health) Prune() {
	h.mu.Lock()
	defer h.mu.Unlock()
	nowMinute := minuteOf(h.now())
	fromMinute := nowMinute - int64(h.windowMins) + 1
	for host, s := range h.sites {
		if s.aggregate(fromMinute, nowMinute).Reqs == 0 {
			delete(h.sites, host)
		}
	}
}
