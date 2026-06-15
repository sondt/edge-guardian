package app

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/sondt/edge-guardian/internal/health"
	"github.com/sondt/edge-guardian/internal/notify"
)

// ProcessLine runs the pipeline for one log line: for each detector, inspect the line → on a
// hit, allowlist → dedup → threshold → ban. Detector patterns are disjoint so at most one
// detector matches; the first match wins. Split out so unit tests don't need a channel/tail.
func (a *App) ProcessLine(line string) {
	now := a.now()
	for _, det := range a.d.Detectors {
		ip, sub, reason, ok := det.Inspect(line)
		if !ok {
			continue
		}
		a.handleHit(det, ip, sub, reason, now)
		return
	}
}

// handleHit processes a line that matched a detector: check allowlist, dedup, threshold, then ban.
func (a *App) handleHit(det *Detector, ip, sub, reason string, now time.Time) {
	addr, err := parseAddr(ip)
	if err != nil {
		a.d.Logger.Debug("skip unparsable ip", "detector", det.Name, "ip", ip, "err", err)
		return
	}
	if a.d.Allow.Contains(addr) {
		a.d.Logger.Debug("allowlisted, skip", "detector", det.Name, "ip", ip)
		return
	}

	// Normalize the key (e.g. "::ffff:1.2.3.4" → "1.2.3.4") so state/window keying is
	// consistent with `edge-guardian unban`, which also keys on addr.String().
	key := addr.String()

	// Already banned (still valid): just add the hit, do NOT re-notify.
	if a.d.State.IsBanned(key, now) {
		a.d.State.RecordHit(key)
		return
	}

	count, tripped := det.Window.Record(key, sub, now)
	if !tripped {
		a.d.Logger.Debug("hit below threshold", "detector", det.Name, "ip", key, "count", count)
		return
	}

	a.ban(det, addr, key, reason, count, now)
}

// ban carries out the ban decision: update state, (except on dry-run) add to nftables,
// save state, and send a notification.
func (a *App) ban(det *Detector, addr netip.Addr, ip, reason string, hits int, now time.Time) {
	// Escalating ban: the number of prior bans (kept in state across the memory window)
	// determines this ban's duration.
	prior, _ := a.d.State.Get(ip)
	dur := banDurationFor(prior.BanCount, a.d.Escalation, a.d.BanDuration)
	expires := now.Add(dur)

	entry := a.d.State.Ban(ip, det.Name, reason, hits, now, expires)
	det.Window.Forget(ip)

	if a.d.DryRun {
		a.d.Logger.Info("dry-run: WOULD ban", "detector", det.Name, "ip", ip, "reason", reason,
			"hits", entry.Hits, "offense", entry.BanCount, "duration", dur)
	} else {
		if err := a.d.Enforcer.Ban(addr, dur); err != nil {
			a.d.Logger.Error("nftables ban failed", "ip", ip, "err", err)
		} else {
			a.d.Logger.Info("banned", "detector", det.Name, "ip", ip, "reason", reason, "hits", entry.Hits,
				"offense", entry.BanCount, "duration", dur, "until", expires.UTC().Format(time.RFC3339))
		}
	}

	if err := a.d.State.Save(); err != nil {
		a.d.Logger.Error("save state after ban", "ip", ip, "err", err)
	}

	geo := a.d.GeoIP.Lookup(ip)
	country, asn := geoFields(geo)

	action := "banned"
	if a.d.DryRun {
		action = "would-ban"
	}
	a.d.Events.Push(now, ip, det.Name, action, country, asn)

	a.notifyEvent(ip, reason, entry.Hits, expires, country, asn, geo.Place())
}

func (a *App) notifyEvent(ip, reason string, hits int, expires time.Time, country, asn, location string) {
	ev := notify.Event{
		IP:        ip,
		URI:       reason,
		Hits:      hits,
		ExpiresAt: expires,
		Country:   country,
		ASN:       asn,
		Location:  location,
		DryRun:    a.d.DryRun,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := a.d.Notifier.Notify(ctx, ev); err != nil {
		a.d.Logger.Error("notify failed", "ip", ip, "err", err)
	}
}

// observeHealth feeds a log line into the health branch (every line, O(1)). No-op if disabled
// or the line doesn't parse. Unlike detection: it does NOT ban, only increments per-site counters.
func (a *App) observeHealth(line string) {
	if a.d.Health == nil || a.d.HealthParser == nil {
		return
	}
	ev, ok := a.d.HealthParser.Parse(line)
	if !ok {
		return
	}
	upstreamErr := ev.Status == 502 || ev.Status == 503 || ev.Status == 504
	now := a.now()
	a.d.Health.Observe(ev.Host, ev.Status, ev.RequestTime, ev.Bytes, upstreamErr, now)
	// Record client/server error responses for the /errors page.
	if ev.Status >= 400 {
		a.d.Errors.PushError(now, ev.Host, ev.IP, ev.URI, ev.Status)
	}
}

// evaluateHealth snapshots the sites and sends alerts (firing/recovered) via the Notifier.
// Called periodically (every minute).
func (a *App) evaluateHealth() {
	if a.d.Health == nil || a.d.HealthAlerter == nil {
		return
	}
	now := a.now()
	stats := a.d.Health.SnapshotAll(a.d.HealthAlertWindow)
	for _, al := range a.d.HealthAlerter.Evaluate(stats, now) {
		a.notifyHealth(al)
	}
}

func (a *App) notifyHealth(al health.Alert) {
	a.d.Logger.Info("health alert", "site", al.Site, "firing", al.Firing,
		"reason", al.Reason, "summary", al.Summary)
	ev := notify.HealthEvent{Site: al.Site, Firing: al.Firing, Summary: al.Summary, Detail: al.Detail}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := a.d.Notifier.NotifyHealth(ctx, ev); err != nil {
		a.d.Logger.Error("health notify failed", "site", al.Site, "err", err)
	}
}

// parseAddr normalizes an IP string into a netip.Addr (strips IPv4-mapped IPv6).
func parseAddr(ip string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse ip %q: %w", ip, err)
	}
	return addr.Unmap(), nil
}
