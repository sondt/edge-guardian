package web

import (
	"fmt"
	"strings"
)

// Sentinel SVG is drawn in an abstract coordinate space then stretched to fill its
// container via preserveAspectRatio="none". Keeping the math in one place makes the
// templ markup declarative.
const (
	sentinelVBWidth  = 1000.0 // viewBox width units
	sentinelVBHeight = 100.0  // viewBox height units
	sentinelTickGap  = 1.0    // horizontal gap between tick slots, in viewBox units
	tickMinHeight    = 4.0    // a present-but-mild event still shows a stub
)

func sentinelViewBox() string {
	return fmt.Sprintf("0 0 %g %g", sentinelVBWidth, sentinelVBHeight)
}

func sentinelWidth() string { return fmt.Sprintf("%g", sentinelVBWidth) }

func sentinelBaselineY() string { return fmt.Sprintf("%g", sentinelVBHeight-1) }

// slotWidth is the per-bucket horizontal slot width.
func slotWidth() float64 {
	return sentinelVBWidth / float64(SentinelBuckets)
}

func tickWidth() string {
	w := slotWidth() - sentinelTickGap
	if w < 1 {
		w = 1
	}
	return fmt.Sprintf("%.2f", w)
}

func tickX(i int) string {
	x := float64(i)*slotWidth() + sentinelTickGap/2
	return fmt.Sprintf("%.2f", x)
}

// tickHeight maps severity (0..1) to a height in viewBox units, with a small floor so
// every real event is visible.
func tickHeightVal(t SentinelTick) float64 {
	h := t.Severity * (sentinelVBHeight - 2)
	if h < tickMinHeight {
		h = tickMinHeight
	}
	return h
}

func tickHeight(t SentinelTick) string {
	return fmt.Sprintf("%.2f", tickHeightVal(t))
}

// tickY anchors ticks to the baseline (they grow upward from the bottom).
func tickY(t SentinelTick) string {
	y := sentinelVBHeight - 1 - tickHeightVal(t)
	if y < 0 {
		y = 0
	}
	return fmt.Sprintf("%.2f", y)
}

// tickStyle carries intensity as the alert-color opacity. Color itself is set in CSS
// (via currentColor / the --alert token) so the SVG stays themeable and CSP-clean.
func tickStyle(t SentinelTick) string {
	return fmt.Sprintf("opacity:%.3f", clamp01(0.18+0.82*t.Intensity))
}

func barWidth(share float64) string {
	w := clamp01(share) * 100
	return fmt.Sprintf("width:%.1f%%", w)
}

func chipLabel(state string) string {
	if strings.TrimSpace(state) == "" {
		return "Quiet"
	}
	return state
}

// sentinelLabel is the accessible text alternative for the whole strip.
func sentinelLabel(m Metrics) string {
	if m.TotalEvents == 0 {
		return "Sentinel line: quiet, no recent detections"
	}
	return fmt.Sprintf("Sentinel line: %s, %d events, %d banned in the recent window",
		strings.ToLower(chipLabel(m.State)), m.TotalEvents, m.Banned)
}
