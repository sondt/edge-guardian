// Package notify sends notifications on each new ban through a common interface.
package notify

import (
	"context"
	"time"
)

// Event is the data of a ban notification.
type Event struct {
	IP        string
	URI       string
	Hits      int
	ExpiresAt time.Time
	Country   string // optional (GeoIP)
	ASN       string // optional (GeoIP)
	Location  string // optional (GeoIP) — human "City, Region, Country"
	DryRun    bool   // true: only "WOULD ban", no actual blocking
}

// HealthEvent is a site health alert (firing = degraded/down, !firing = recovered).
// Unlike Event (ban): no IP/ban — this is a site status.
type HealthEvent struct {
	Site    string
	Firing  bool
	Summary string // headline, e.g. "5xx 12.4% (threshold 5%)"
	Detail  string // metrics line, e.g. "req/s 240 · p95 1.8s"
}

// Notifier is the common interface for every notification channel (Telegram, Email, webhook...).
type Notifier interface {
	Notify(ctx context.Context, ev Event) error
	NotifyHealth(ctx context.Context, ev HealthEvent) error
}

// Noop is a Notifier that does nothing — used when all channels are disabled.
type Noop struct{}

// Notify on Noop always succeeds.
func (Noop) Notify(context.Context, Event) error { return nil }

// NotifyHealth on Noop always succeeds.
func (Noop) NotifyHealth(context.Context, HealthEvent) error { return nil }
