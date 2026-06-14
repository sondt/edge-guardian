package blocklist

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"time"
)

// Applier nạp tập prefix blocklist vào tầng thực thi (nftables interval set).
// *enforce.Enforcer thoả mãn interface này.
type Applier interface {
	ReplaceBlockset(v4, v6 []netip.Prefix) error
}

// Importer tải các blocklist công khai định kỳ và nạp vào nftables. Triển khai
// app.Service (Start/Name).
type Importer struct {
	urls     []string
	allow    excluder
	applier  Applier
	interval time.Duration
	client   *http.Client
	log      *slog.Logger
}

// NewImporter tạo importer. interval <= 0 → mặc định 24h.
func NewImporter(urls []string, allow excluder, applier Applier, interval time.Duration, log *slog.Logger) *Importer {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	if log == nil {
		log = slog.Default()
	}
	return &Importer{
		urls:     append([]string(nil), urls...),
		allow:    allow,
		applier:  applier,
		interval: interval,
		client:   &http.Client{Timeout: 60 * time.Second},
		log:      log,
	}
}

// Name định danh service.
func (i *Importer) Name() string { return "blocklist-import" }

// Start nạp ngay một lần rồi làm mới theo chu kỳ cho tới khi ctx hủy. Best-effort:
// nguồn lỗi / apply lỗi chỉ log, không dừng daemon.
func (i *Importer) Start(ctx context.Context) error {
	i.refresh(ctx)

	t := time.NewTicker(i.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			i.refresh(ctx)
		}
	}
}

func (i *Importer) refresh(ctx context.Context) {
	set, errs := FetchAll(ctx, i.client, i.urls, i.allow)
	for _, err := range errs {
		i.log.Warn("blocklist source failed", "err", err)
	}
	if set.Len() == 0 {
		i.log.Warn("blocklist import: no prefixes loaded (all sources failed?)")
		return
	}
	if err := i.applier.ReplaceBlockset(set.V4, set.V6); err != nil {
		i.log.Error("blocklist import: apply to nftables failed", "err", err)
		return
	}
	i.log.Info("blocklist imported", "v4", len(set.V4), "v6", len(set.V6), "sources", len(i.urls))
}
