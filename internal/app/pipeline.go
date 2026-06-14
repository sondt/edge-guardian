package app

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/sondt/edge-guardian/internal/health"
	"github.com/sondt/edge-guardian/internal/notify"
)

// ProcessLine chạy pipeline cho một dòng log: với mỗi detector, soi dòng → nếu hit
// thì allowlist → dedup → ngưỡng → ban. Các pattern detector rời nhau nên tối đa một
// detector khớp; khớp đầu tiên thắng. Tách riêng để unit-test không cần channel/tail.
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

// handleHit xử lý một dòng đã khớp detector: kiểm allowlist, dedup, ngưỡng, rồi ban.
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

	// Đã bị ban (còn hạn): chỉ cộng hit, KHÔNG thông báo lại.
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

// ban thực thi quyết định ban: cập nhật state, (trừ dry-run) thêm vào nftables,
// lưu state và gửi thông báo.
func (a *App) ban(det *Detector, addr netip.Addr, ip, reason string, hits int, now time.Time) {
	// Ban leo thang: số lần đã bị ban trước đó (giữ trong state qua memory window)
	// quyết định thời gian ban lần này.
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

	country, asn := geoFields(a.d.GeoIP.Lookup(ip))

	action := "banned"
	if a.d.DryRun {
		action = "would-ban"
	}
	a.d.Events.Push(now, ip, det.Name, action, country, asn)

	a.notifyEvent(ip, reason, entry.Hits, expires, country, asn)
}

func (a *App) notifyEvent(ip, reason string, hits int, expires time.Time, country, asn string) {
	ev := notify.Event{
		IP:        ip,
		URI:       reason,
		Hits:      hits,
		ExpiresAt: expires,
		Country:   country,
		ASN:       asn,
		DryRun:    a.d.DryRun,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := a.d.Notifier.Notify(ctx, ev); err != nil {
		a.d.Logger.Error("notify failed", "ip", ip, "err", err)
	}
}

// observeHealth nạp một dòng log vào nhánh health (mọi dòng, O(1)). No-op nếu tắt hoặc
// dòng không parse được. Khác detection: KHÔNG ban, chỉ tăng counter per-site.
func (a *App) observeHealth(line string) {
	if a.d.Health == nil || a.d.HealthParser == nil {
		return
	}
	ev, ok := a.d.HealthParser.Parse(line)
	if !ok {
		return
	}
	upstreamErr := ev.Status == 502 || ev.Status == 503 || ev.Status == 504
	a.d.Health.Observe(ev.Host, ev.Status, ev.RequestTime, ev.Bytes, upstreamErr, a.now())
}

// evaluateHealth chụp các site và gửi cảnh báo (firing/recovered) qua Notifier. Gọi định
// kỳ (mỗi phút).
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

// parseAddr chuẩn hóa chuỗi IP thành netip.Addr (gỡ IPv4-mapped IPv6).
func parseAddr(ip string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse ip %q: %w", ip, err)
	}
	return addr.Unmap(), nil
}
