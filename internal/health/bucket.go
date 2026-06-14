package health

// Bucket là tổng hợp 1 phút cho một site. Chỉ counter — không giữ request.
type Bucket struct {
	minute      int64 // phút Unix bucket này đại diện; -1 = slot rỗng/chưa dùng
	Reqs        uint64
	Status      [6]uint64 // đánh chỉ số theo class = status/100: [1]=1xx … [5]=5xx; [0] không dùng
	Bytes       uint64
	UpstreamErr uint64 // 502/503/504
	Lat         LatencyHist
}

// reset đưa bucket về rỗng và gắn cho phút mới (tái dùng slot ring).
func (b *Bucket) reset(minute int64) {
	*b = Bucket{minute: minute}
}

// observe cộng một quan sát vào bucket.
func (b *Bucket) observe(status int, rtSec float64, bytes uint64, upstreamErr bool) {
	b.Reqs++
	if class := status / 100; class >= 1 && class <= 5 {
		b.Status[class]++
	}
	b.Bytes += bytes
	if upstreamErr {
		b.UpstreamErr++
	}
	if rtSec > 0 {
		b.Lat.Observe(rtSec)
	}
}

// SiteSeries là ring buffer các bucket phút cho một site. Slot đánh chỉ số theo
// (minute mod len); mỗi slot mang phút của nó để nhận biết slot cũ (gap) và tự reset.
type SiteSeries struct {
	buckets []Bucket
}

// newSeries tạo series với n slot phút (n = số phút giữ trong RAM).
func newSeries(n int) *SiteSeries {
	if n < 1 {
		n = 1
	}
	bs := make([]Bucket, n)
	for i := range bs {
		bs[i].minute = -1
	}
	return &SiteSeries{buckets: bs}
}

// bucketFor trả về con trỏ bucket cho phút minute, reset nếu slot đang giữ phút khác
// (slot cũ bị ghi đè — đó chính là cách ring "quên" dữ liệu ngoài cửa sổ).
func (s *SiteSeries) bucketFor(minute int64) *Bucket {
	b := &s.buckets[((minute%int64(len(s.buckets)))+int64(len(s.buckets)))%int64(len(s.buckets))]
	if b.minute != minute {
		b.reset(minute)
	}
	return b
}

// observe ghi một quan sát vào bucket của phút minute.
func (s *SiteSeries) observe(minute int64, status int, rtSec float64, bytes uint64, upstreamErr bool) {
	s.bucketFor(minute).observe(status, rtSec, bytes, upstreamErr)
}

// aggregate gộp các bucket có phút trong [fromMinute, nowMinute] thành một Bucket tổng.
// Slot ngoài khoảng (gồm slot rỗng minute=-1 và slot mang phút cũ đã bị vòng) bị bỏ qua.
func (s *SiteSeries) aggregate(fromMinute, nowMinute int64) Bucket {
	var agg Bucket
	for i := range s.buckets {
		b := &s.buckets[i]
		if b.minute < fromMinute || b.minute > nowMinute {
			continue
		}
		agg.Reqs += b.Reqs
		for c := range agg.Status {
			agg.Status[c] += b.Status[c]
		}
		agg.Bytes += b.Bytes
		agg.UpstreamErr += b.UpstreamErr
		agg.Lat.merge(b.Lat)
	}
	return agg
}

// perMinuteReqs trả về số request mỗi phút trong [fromMinute, nowMinute], theo thứ tự
// thời gian tăng dần (cho sparkline). Phút không có dữ liệu = 0.
func (s *SiteSeries) perMinuteReqs(fromMinute, nowMinute int64) []int {
	n := int(nowMinute - fromMinute + 1)
	if n < 1 {
		return nil
	}
	out := make([]int, n)
	for i := range s.buckets {
		b := &s.buckets[i]
		if b.minute < fromMinute || b.minute > nowMinute {
			continue
		}
		out[b.minute-fromMinute] = int(b.Reqs)
	}
	return out
}
