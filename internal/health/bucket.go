package health

// Bucket is a 1-minute aggregate for a site. Counters only — it does not retain requests.
type Bucket struct {
	minute      int64 // Unix minute this bucket represents; -1 = empty/unused slot
	Reqs        uint64
	Status      [6]uint64 // indexed by class = status/100: [1]=1xx … [5]=5xx; [0] unused
	Bytes       uint64
	UpstreamErr uint64 // 502/503/504
	Lat         LatencyHist
}

// reset empties the bucket and assigns it to a new minute (reusing the ring slot).
func (b *Bucket) reset(minute int64) {
	*b = Bucket{minute: minute}
}

// observe adds one observation to the bucket.
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

// SiteSeries is a ring buffer of minute buckets for a site. Slots are indexed by
// (minute mod len); each slot carries its own minute so stale slots (gaps) can be detected and self-reset.
type SiteSeries struct {
	buckets []Bucket
}

// newSeries creates a series with n minute slots (n = number of minutes kept in RAM).
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

// bucketFor returns the bucket pointer for minute, resetting it if the slot holds a different minute
// (the old slot is overwritten — this is how the ring "forgets" data outside the window).
func (s *SiteSeries) bucketFor(minute int64) *Bucket {
	b := &s.buckets[((minute%int64(len(s.buckets)))+int64(len(s.buckets)))%int64(len(s.buckets))]
	if b.minute != minute {
		b.reset(minute)
	}
	return b
}

// observe records one observation into the bucket for the given minute.
func (s *SiteSeries) observe(minute int64, status int, rtSec float64, bytes uint64, upstreamErr bool) {
	s.bucketFor(minute).observe(status, rtSec, bytes, upstreamErr)
}

// aggregate merges buckets whose minute is in [fromMinute, nowMinute] into one combined Bucket.
// Slots outside the range (including empty slots minute=-1 and slots holding a wrapped-over old minute) are skipped.
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

// perMinuteReqs returns the request count per minute in [fromMinute, nowMinute], in ascending
// time order (for the sparkline). Minutes with no data = 0.
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
