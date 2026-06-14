// Package health theo dõi "sức khỏe biên" từ cùng access log mà detection đọc: với MỌI
// dòng nó chỉ tăng counter tổng hợp per-site (O(1), không giữ lại request), rồi cảnh báo
// khi site degraded/down. KHÔNG ban IP — đó là việc của nhánh detection.
package health

// latencyBoundsSecArr là cận trên (giây) của các bucket histogram latency. Cố định để
// ước lượng quantile mà không lưu từng mẫu. Bucket cuối (+Inf) nằm sau cận cuối cùng.
var latencyBoundsSecArr = [10]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

// nLatBuckets = số cận + 1 (bucket +Inf cho mẫu vượt cận cuối).
const nLatBuckets = len(latencyBoundsSecArr) + 1

// LatencyHist là histogram latency với các bucket cận cố định. Cộng dồn được (merge khi
// snapshot nhiều bucket phút). Giá trị, không con trỏ — copy rẻ.
type LatencyHist struct {
	counts [nLatBuckets]uint64
	total  uint64
}

// Observe ghi một mẫu latency (giây) vào bucket tương ứng. Mẫu < 0 bị bỏ qua (latency
// không hợp lệ, vd log thiếu request_time = 0 vẫn tính là 0ms hợp lệ).
func (h *LatencyHist) Observe(sec float64) {
	if sec < 0 {
		return
	}
	idx := nLatBuckets - 1 // mặc định bucket +Inf
	for i, b := range latencyBoundsSecArr {
		if sec <= b {
			idx = i
			break
		}
	}
	h.counts[idx]++
	h.total++
}

// merge cộng dồn o vào h (dùng khi gộp các bucket phút trong cửa sổ snapshot).
func (h *LatencyHist) merge(o LatencyHist) {
	for i := range h.counts {
		h.counts[i] += o.counts[i]
	}
	h.total += o.total
}

// reset đưa histogram về rỗng (tái dùng slot ring khi sang phút mới).
func (h *LatencyHist) reset() { *h = LatencyHist{} }

// Count trả về tổng số mẫu.
func (h *LatencyHist) Count() uint64 { return h.total }

// Quantile ước lượng quantile q (0..1) bằng nội suy tuyến tính trong bucket chứa mốc
// q*total. Trả về giây. Rỗng → 0. Mốc rơi vào bucket +Inf → trả cận hữu hạn cuối cùng
// (không thể nội suy mẫu vô cực).
func (h *LatencyHist) Quantile(q float64) float64 {
	if h.total == 0 {
		return 0
	}
	if q < 0 {
		q = 0
	}
	if q > 1 {
		q = 1
	}
	target := q * float64(h.total)
	var cum float64
	lower := 0.0
	for i := range latencyBoundsSecArr {
		c := float64(h.counts[i])
		if cum+c >= target {
			upper := latencyBoundsSecArr[i]
			// Nội suy tuyến tính trong bucket [lower, upper] theo vị trí của target.
			if c == 0 {
				return upper
			}
			frac := (target - cum) / c
			return lower + frac*(upper-lower)
		}
		cum += c
		lower = latencyBoundsSecArr[i]
	}
	// Rơi vào bucket +Inf: trả cận hữu hạn cuối cùng làm cận dưới ước lượng.
	return latencyBoundsSecArr[len(latencyBoundsSecArr)-1]
}
