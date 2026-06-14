package health

import (
	"math"
	"testing"
)

func TestLatencyHist_Empty(t *testing.T) {
	var h LatencyHist
	if h.Count() != 0 {
		t.Fatalf("empty count=%d", h.Count())
	}
	if q := h.Quantile(0.95); q != 0 {
		t.Fatalf("empty quantile=%v want 0", q)
	}
}

func TestLatencyHist_QuantileMonotonic(t *testing.T) {
	var h LatencyHist
	// 100 samples spread across buckets.
	for i := 0; i < 100; i++ {
		h.Observe(float64(i) / 100.0) // 0..0.99s
	}
	p50 := h.Quantile(0.50)
	p95 := h.Quantile(0.95)
	p99 := h.Quantile(0.99)
	if !(p50 <= p95 && p95 <= p99) {
		t.Fatalf("quantiles not monotonic: p50=%v p95=%v p99=%v", p50, p95, p99)
	}
	if h.Count() != 100 {
		t.Fatalf("count=%d want 100", h.Count())
	}
}

func TestLatencyHist_QuantileBucketed(t *testing.T) {
	var h LatencyHist
	// All samples ~1ms → land in the first bucket (<=5ms). p95 should be small.
	for i := 0; i < 50; i++ {
		h.Observe(0.001)
	}
	if q := h.Quantile(0.95); q > 0.005+1e-9 {
		t.Fatalf("p95=%v want <= first bound 5ms", q)
	}

	// Heavy tail: half fast, half very slow (>5s → +Inf bucket).
	var h2 LatencyHist
	for i := 0; i < 50; i++ {
		h2.Observe(0.001)
	}
	for i := 0; i < 50; i++ {
		h2.Observe(10) // beyond last bound
	}
	if q := h2.Quantile(0.99); q < latencyBoundsSecArr[len(latencyBoundsSecArr)-1] {
		t.Fatalf("p99=%v want >= last finite bound %v", q, latencyBoundsSecArr[len(latencyBoundsSecArr)-1])
	}
}

func TestLatencyHist_Merge(t *testing.T) {
	var a, b LatencyHist
	for i := 0; i < 10; i++ {
		a.Observe(0.01)
	}
	for i := 0; i < 5; i++ {
		b.Observe(2.0)
	}
	a.merge(b)
	if a.Count() != 15 {
		t.Fatalf("merged count=%d want 15", a.Count())
	}
}

func TestLatencyHist_NegativeIgnored(t *testing.T) {
	var h LatencyHist
	h.Observe(-1)
	if h.Count() != 0 {
		t.Fatal("negative latency must be ignored")
	}
}

func approx(a, b, eps float64) bool { return math.Abs(a-b) <= eps }
