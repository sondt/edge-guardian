package health

import "sort"

// Thresholds là ngưỡng dùng để phân loại trạng thái site trên dashboard (khớp với
// ngưỡng cảnh báo trong config [health]).
type Thresholds struct {
	Err5xxRatio float64 // 0..1; vượt = degraded
	P95Sec      float64 // giây; 0 = không xét latency
}

// SiteStats là ảnh chụp sức khỏe một site trong cửa sổ — read model cho dashboard + alert.
type SiteStats struct {
	Host       string
	WindowMins int

	Reqs      uint64
	ReqPerSec float64

	Status2xx uint64
	Status3xx uint64
	Status4xx uint64
	Status5xx uint64

	Err5xxRatio float64 // 0..1

	HasLatency bool
	P50Sec     float64
	P95Sec     float64
	P99Sec     float64

	UpstreamErr uint64

	Spark  []int  // số request mỗi phút (cũ → mới)
	Status string // "Healthy" | "Degraded" | "Down" | "Idle"
}

// classify đặt trường Status theo ngưỡng và lưu lượng gần đây.
//   - Idle  : không có request nào trong cửa sổ (site yên, không báo động).
//   - Down  : có lưu lượng trong cửa sổ nhưng ~0 trong 2 phút gần nhất (rớt về 0).
//   - Degraded: vượt ngưỡng 5xx hoặc p95.
//   - Healthy: còn lại.
func (s *SiteStats) classify(th Thresholds, recentReqs uint64) {
	switch {
	case s.Reqs == 0:
		s.Status = "Idle"
	case recentReqs == 0:
		s.Status = "Down"
	case s.Err5xxRatio > th.Err5xxRatio:
		s.Status = "Degraded"
	case th.P95Sec > 0 && s.HasLatency && s.P95Sec > th.P95Sec:
		s.Status = "Degraded"
	default:
		s.Status = "Healthy"
	}
}

// byHost sắp xếp danh sách SiteStats theo host (ổn định cho dashboard).
func byHost(stats []SiteStats) {
	sort.Slice(stats, func(i, j int) bool { return stats[i].Host < stats[j].Host })
}
