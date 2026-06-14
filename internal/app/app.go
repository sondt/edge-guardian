// Package app lắp ráp các thành phần và chạy vòng lặp daemon.
package app

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/sondt/edge-guardian/internal/allow"
	"github.com/sondt/edge-guardian/internal/enforce"
	"github.com/sondt/edge-guardian/internal/geoip"
	"github.com/sondt/edge-guardian/internal/health"
	"github.com/sondt/edge-guardian/internal/ingest"
	"github.com/sondt/edge-guardian/internal/notify"
	"github.com/sondt/edge-guardian/internal/parse"
	"github.com/sondt/edge-guardian/internal/state"
)

// Deps gom mọi phụ thuộc của App; cho phép inject fake khi test.
type Deps struct {
	Detectors []*Detector // các nguồn phát hiện (http, sshd, ...)
	Paths     []string    // hợp các file log cần tail (cho tailer)
	Allow     *allow.List
	State     *state.Store
	Enforcer  enforce.Enforcer
	Notifier  notify.Notifier
	GeoIP     GeoIP

	BanDuration time.Duration // ban phẳng (khi escalation rỗng)

	// Escalation: thời gian ban leo thang theo số lần tái phạm (rỗng = ban phẳng).
	// EscalationMemory: giữ lịch sử offender bao lâu sau khi ban hết hạn (để đếm tái phạm).
	Escalation       []time.Duration
	EscalationMemory time.Duration

	DryRun bool
	Logger *slog.Logger

	// Events nhận sự kiện phát hiện (cho dashboard); nil => bỏ qua.
	Events EventSink

	// Nhánh health (tùy chọn). Health == nil => tắt hoàn toàn. Đọc MỌI dòng log để
	// tổng hợp counter per-site và cảnh báo trạng thái — KHÔNG ban IP.
	Health            *health.Health
	HealthAlerter     *health.Alerter   // nil => không gửi cảnh báo
	HealthParser      *parse.LineParser // parse host/status/latency cho health
	HealthWindow      int               // cửa sổ (phút) cho snapshot dashboard
	HealthAlertWindow int               // cửa sổ (phút) cho đánh giá cảnh báo

	// Now cho phép kiểm soát thời gian trong test; nil => time.Now.
	Now func() time.Time
}

// GeoIP giải IP nguồn → vị trí/mạng. *geoip.Resolver và geoip.Nop thoả mãn.
type GeoIP interface {
	Lookup(ip string) geoip.Result
}

// EventSink nhận mỗi sự kiện ban/would-ban để hiển thị realtime (dashboard).
// Tách interface để hot-path không phụ thuộc cứng vào package web.
type EventSink interface {
	Push(at time.Time, ip, detector, action, country, asn string)
}

// noopSink bỏ qua mọi sự kiện.
type noopSink struct{}

func (noopSink) Push(time.Time, string, string, string, string, string) {}

// Service là một tiến trình nền chạy cùng daemon (control socket, dashboard...).
type Service interface {
	// Start chạy cho tới khi ctx hủy; trả lỗi nếu không khởi động được.
	Start(ctx context.Context) error
	// Name dùng cho log.
	Name() string
}

// App là daemon đã lắp ráp.
type App struct {
	d   Deps
	now func() time.Time
}

// New tạo App từ Deps đã chuẩn bị sẵn.
func New(d Deps) *App {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Notifier == nil {
		d.Notifier = notify.Noop{}
	}
	if d.GeoIP == nil {
		d.GeoIP = geoip.Nop{}
	}
	if d.Events == nil {
		d.Events = noopSink{}
	}
	return &App{d: d, now: now}
}

const (
	saveInterval  = 30 * time.Second
	pruneInterval = 5 * time.Minute
	alertInterval = 1 * time.Minute // chu kỳ đánh giá cảnh báo health
)

// Paths returns the log files the daemon needs to tail (union across detectors).
func (a *App) Paths() []string { return a.d.Paths }

// Run khôi phục state vào nftables, khởi động các service nền (control socket,
// dashboard...), rồi tiêu thụ log cho tới khi ctx hủy.
func (a *App) Run(ctx context.Context, tailer *ingest.Tailer, services ...Service) error {
	a.Restore(ctx)

	var svcWG sync.WaitGroup
	for _, svc := range services {
		a.d.Logger.Info("starting service", "name", svc.Name())
		svcWG.Add(1)
		go func() {
			defer svcWG.Done()
			if err := svc.Start(ctx); err != nil && ctx.Err() == nil {
				a.d.Logger.Error("service stopped with error", "name", svc.Name(), "err", err)
			}
		}()
	}
	// Drain service goroutines before returning so the caller's Cleanup (which closes
	// the nftables connection) cannot race an in-flight unban from a service.
	defer svcWG.Wait()

	lines, err := tailer.Run(ctx)
	if err != nil {
		return err
	}

	saveTicker := time.NewTicker(saveInterval)
	defer saveTicker.Stop()
	pruneTicker := time.NewTicker(pruneInterval)
	defer pruneTicker.Stop()
	alertTicker := time.NewTicker(alertInterval)
	defer alertTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.d.State.Prune(a.now(), a.d.EscalationMemory)
			if err := a.d.State.Save(); err != nil {
				a.d.Logger.Error("save state on shutdown", "err", err)
			}
			return ctx.Err()

		case <-saveTicker.C:
			if err := a.d.State.Save(); err != nil {
				a.d.Logger.Error("periodic save state", "err", err)
			}

		case <-pruneTicker.C:
			now := a.now()
			for _, det := range a.d.Detectors {
				det.Window.Prune(now)
			}
			if n := a.d.State.Prune(now, a.d.EscalationMemory); n > 0 {
				a.d.Logger.Debug("pruned expired bans from state", "count", n)
			}
			if a.d.Health != nil {
				a.d.Health.Prune()
			}

		case <-alertTicker.C:
			a.evaluateHealth()

		case ln, ok := <-lines:
			if !ok {
				return nil
			}
			a.ProcessLine(ln.Text)
			a.observeHealth(ln.Text)
		}
	}
}

// Restore nạp lại các IP còn hạn từ state vào nftables (set rỗng sau reboot).
// Bỏ qua khi dry-run. Lỗi từng IP được log, không dừng cả quá trình.
func (a *App) Restore(ctx context.Context) {
	now := a.now()
	active := a.d.State.Active(now)
	if a.d.DryRun {
		a.d.Logger.Info("dry-run: skip restoring bans into nftables", "count", len(active))
		return
	}
	restored := 0
	for _, e := range active {
		addr, err := parseAddr(e.IP)
		if err != nil {
			a.d.Logger.Warn("restore: skip invalid ip", "ip", e.IP, "err", err)
			continue
		}
		remaining := e.ExpiresAt.Sub(now)
		if remaining <= 0 {
			continue
		}
		if err := a.d.Enforcer.Ban(addr, remaining); err != nil {
			a.d.Logger.Error("restore ban failed", "ip", e.IP, "err", err)
			continue
		}
		restored++
	}
	a.d.Logger.Info("restored bans from state", "restored", restored, "total", len(active))
}
