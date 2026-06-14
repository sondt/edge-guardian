// Package notify gửi thông báo khi có ban mới qua một interface chung.
package notify

import (
	"context"
	"time"
)

// Event là dữ liệu một thông báo ban.
type Event struct {
	IP        string
	URI       string
	Hits      int
	ExpiresAt time.Time
	Country   string // tùy chọn (GeoIP)
	ASN       string // tùy chọn (GeoIP)
	DryRun    bool   // true: chỉ "SẼ ban", không thực sự chặn
}

// HealthEvent là một cảnh báo sức khỏe site (firing = degraded/down, !firing = recovered).
// Khác Event (ban): không có IP/ban — đây là trạng thái site.
type HealthEvent struct {
	Site    string
	Firing  bool
	Summary string // dòng tiêu đề, vd "5xx 12.4% (threshold 5%)"
	Detail  string // dòng số liệu, vd "req/s 240 · p95 1.8s"
}

// Notifier là interface chung cho mọi kênh thông báo (Telegram, Email, webhook...).
type Notifier interface {
	Notify(ctx context.Context, ev Event) error
	NotifyHealth(ctx context.Context, ev HealthEvent) error
}

// Noop là Notifier không làm gì — dùng khi tắt mọi kênh.
type Noop struct{}

// Notify trên Noop luôn thành công.
func (Noop) Notify(context.Context, Event) error { return nil }

// NotifyHealth trên Noop luôn thành công.
func (Noop) NotifyHealth(context.Context, HealthEvent) error { return nil }
