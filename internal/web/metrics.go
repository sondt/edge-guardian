package web

import (
	"sort"
	"strings"
	"time"
)

// maxOriginRows caps the origin ranking so the panel stays an instrument, not a log.
const maxOriginRows = 5

// scanThreshold is the per-bucket event count above which the headline state flips to
// "Under scan". Tuned for the SentinelBuckets window: a few events per slice is normal
// noise; a spike means someone is actively probing.
const scanThreshold = 6

// aggregate turns a time-ordered slice of events into Metrics. It is pure: given the
// same events and now, it always returns the same value (deterministic for tests).
func aggregate(events []Event, now time.Time, retention time.Duration) Metrics {
	m := Metrics{
		GeneratedAt: now,
		State:       "Quiet",
		Sentinel:    make([]SentinelTick, SentinelBuckets),
		EventsSpark: make([]int, SparkBuckets),
		BannedSpark: make([]int, SparkBuckets),
	}

	if retention <= 0 {
		retention = 24 * time.Hour
	}

	// Sentinel covers the most recent slice of time at fine granularity so it reads
	// like a live trace. We use the last `sentinelWindow` of activity.
	sentinelWindow := retention
	if sentinelWindow > 6*time.Hour {
		sentinelWindow = 6 * time.Hour // recent exposure, not the whole day
	}
	sentinelStart := now.Add(-sentinelWindow)
	sentinelStep := sentinelWindow / time.Duration(SentinelBuckets)

	// Sparkline covers the full retention window in SparkBuckets equal slices.
	sparkStart := now.Add(-retention)
	sparkStep := retention / time.Duration(SparkBuckets)

	// Accumulators.
	type bucketAcc struct {
		count    int
		banned   int
		wouldBan int
		maxSev   float64
	}
	sentBuckets := make([]bucketAcc, SentinelBuckets)
	origins := map[string]int{}
	detectors := map[string]int{}

	peak := 0

	for _, e := range events {
		if e.At.Before(sparkStart) {
			continue // outside retention; defensive (Store already trims)
		}
		m.TotalEvents++
		banned := e.Action == "banned"
		if banned {
			m.Banned++
		} else {
			m.WouldBan++
		}

		// Sparkline buckets (whole retention window).
		if si := bucketIndex(e.At, sparkStart, sparkStep, SparkBuckets); si >= 0 {
			m.EventsSpark[si]++
			if banned {
				m.BannedSpark[si]++
			}
		}

		// Origin + detector ranking (whole window).
		origins[originLabel(e)]++
		detectors[detectorLabel(e.Detector)]++

		// Sentinel buckets (recent window only).
		if !e.At.Before(sentinelStart) {
			if bi := bucketIndex(e.At, sentinelStart, sentinelStep, SentinelBuckets); bi >= 0 {
				b := &sentBuckets[bi]
				b.count++
				if banned {
					b.banned++
				} else {
					b.wouldBan++
				}
				sev := severity(e)
				if sev > b.maxSev {
					b.maxSev = sev
				}
				if b.count > peak {
					peak = b.count
				}
			}
		}
	}

	// Build sentinel ticks. Height (severity) blends per-event severity with local
	// density; intensity (opacity) scales with how loud the bucket is vs the peak.
	for i := range sentBuckets {
		b := sentBuckets[i]
		if b.count == 0 {
			continue
		}
		density := 0.0
		if peak > 0 {
			density = float64(b.count) / float64(peak)
		}
		// Severity = the hottest event in the bucket, lifted by local density so a
		// burst of mild events still rises. Clamped to 1.
		sev := b.maxSev*0.7 + density*0.3
		m.Sentinel[i] = SentinelTick{
			Severity:  clamp01(sev),
			Intensity: clamp01(0.25 + 0.75*density),
			Hollow:    b.banned == 0 && b.wouldBan > 0,
			Count:     b.count,
		}
	}
	if peak > 0 {
		m.PeakWin = float64(peak)
	}

	// Headline state: under scan if any recent bucket is hot.
	if peak >= scanThreshold {
		m.State = "Under scan"
		m.UnderAtk = true
	}

	m.TopOrigins = rankOrigins(origins, m.TotalEvents)
	m.Detectors = rankDetectors(detectors, m.TotalEvents)
	return m
}

// bucketIndex maps a timestamp to a bucket in [start, start+step*n). Returns -1 if out
// of range (which the caller treats as "skip").
func bucketIndex(at, start time.Time, step time.Duration, n int) int {
	if step <= 0 {
		return -1
	}
	idx := int(at.Sub(start) / step)
	if idx < 0 || idx >= n {
		// Clamp the trailing edge so an event landing exactly at `now` counts.
		if idx == n {
			return n - 1
		}
		return -1
	}
	return idx
}

// severity scores a single event 0..1. Banned events read hotter than would-ban; some
// detectors (portscan, honeypot) signal more aggression than a single http hit.
func severity(e Event) float64 {
	base := 0.45
	switch e.Detector {
	case "portscan":
		base = 0.8
	case "honeypot":
		base = 0.9
	case "exploit":
		base = 0.75
	case "badbot":
		base = 0.55
	case "ratelimit":
		base = 0.7
	case "sshd":
		base = 0.6
	case "http":
		base = 0.5
	}
	if e.Action != "banned" {
		base *= 0.6 // dry-run reads cooler
	}
	return clamp01(base)
}

func originLabel(e Event) string {
	country := strings.TrimSpace(e.Country)
	asn := strings.TrimSpace(e.ASN)
	switch {
	case country != "" && asn != "":
		return country + " · " + asn
	case asn != "":
		return asn
	case country != "":
		return country
	default:
		return "Unknown"
	}
}

func detectorLabel(d string) string {
	d = strings.TrimSpace(d)
	if d == "" {
		return "other"
	}
	return d
}

func rankOrigins(counts map[string]int, total int) []OriginRow {
	rows := make([]OriginRow, 0, len(counts))
	for label, hits := range counts {
		share := 0.0
		if total > 0 {
			share = float64(hits) / float64(total)
		}
		rows = append(rows, OriginRow{Label: label, Hits: hits, Share: share})
	}
	sortOrigins(rows)
	if len(rows) > maxOriginRows {
		rows = rows[:maxOriginRows]
	}
	return rows
}

func rankDetectors(counts map[string]int, total int) []DetectorRow {
	rows := make([]DetectorRow, 0, len(counts))
	for name, hits := range counts {
		share := 0.0
		if total > 0 {
			share = float64(hits) / float64(total)
		}
		rows = append(rows, DetectorRow{Name: name, Hits: hits, Share: share})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Hits != rows[j].Hits {
			return rows[i].Hits > rows[j].Hits
		}
		return rows[i].Name < rows[j].Name
	})
	return rows
}

// sortOrigins sorts OriginRows in place, descending by hits then ascending by label
// for a stable, deterministic order.
func sortOrigins(rows []OriginRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Hits != rows[j].Hits {
			return rows[i].Hits > rows[j].Hits
		}
		return rows[i].Label < rows[j].Label
	})
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
