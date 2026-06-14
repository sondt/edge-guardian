// Package health tracks "edge health" from the same access log that detection reads: for EVERY
// line it only increments per-site aggregate counters (O(1), retaining no requests), then alerts
// when a site is degraded/down. It does NOT ban IPs — that's the detection branch's job.
package health

// latencyBoundsSecArr holds the upper bounds (seconds) of the latency histogram buckets. Fixed so
// quantiles can be estimated without storing every sample. The last bucket (+Inf) lies beyond the final bound.
var latencyBoundsSecArr = [10]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

// nLatBuckets = number of bounds + 1 (the +Inf bucket for samples exceeding the last bound).
const nLatBuckets = len(latencyBoundsSecArr) + 1

// LatencyHist is a latency histogram with fixed bucket bounds. Additive (merged when
// snapshotting multiple minute buckets). A value, not a pointer — cheap to copy.
type LatencyHist struct {
	counts [nLatBuckets]uint64
	total  uint64
}

// Observe records one latency sample (seconds) into the matching bucket. Samples < 0 are dropped (invalid
// latency; e.g. a log missing request_time = 0 still counts as a valid 0ms).
func (h *LatencyHist) Observe(sec float64) {
	if sec < 0 {
		return
	}
	idx := nLatBuckets - 1 // default to the +Inf bucket
	for i, b := range latencyBoundsSecArr {
		if sec <= b {
			idx = i
			break
		}
	}
	h.counts[idx]++
	h.total++
}

// merge adds o into h (used when combining minute buckets within the snapshot window).
func (h *LatencyHist) merge(o LatencyHist) {
	for i := range h.counts {
		h.counts[i] += o.counts[i]
	}
	h.total += o.total
}

// reset empties the histogram (reusing the ring slot when moving to a new minute).
func (h *LatencyHist) reset() { *h = LatencyHist{} }

// Count returns the total number of samples.
func (h *LatencyHist) Count() uint64 { return h.total }

// Quantile estimates quantile q (0..1) by linear interpolation within the bucket containing the
// q*total mark. Returns seconds. Empty → 0. If the mark falls in the +Inf bucket → returns the last finite
// bound (an infinite sample cannot be interpolated).
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
			// Linear interpolation within bucket [lower, upper] based on target's position.
			if c == 0 {
				return upper
			}
			frac := (target - cum) / c
			return lower + frac*(upper-lower)
		}
		cum += c
		lower = latencyBoundsSecArr[i]
	}
	// Falls in the +Inf bucket: return the last finite bound as the lower-bound estimate.
	return latencyBoundsSecArr[len(latencyBoundsSecArr)-1]
}
