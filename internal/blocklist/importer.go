package blocklist

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"time"
)

// Applier loads the blocklist prefix set into the enforcement layer (nftables interval set).
// *enforce.Enforcer satisfies this interface.
type Applier interface {
	ReplaceBlockset(v4, v6 []netip.Prefix) error
}

// Importer periodically downloads public blocklists and loads them into nftables. It
// implements app.Service (Start/Name).
type Importer struct {
	urls     []string
	allow    excluder
	applier  Applier
	interval time.Duration
	client   *http.Client
	log      *slog.Logger
}

// NewImporter creates an importer. interval <= 0 → defaults to 24h.
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

// Name identifies the service.
func (i *Importer) Name() string { return "blocklist-import" }

// Start loads once immediately, then refreshes periodically until ctx is canceled.
// Best-effort: a source error / apply error is only logged and does not stop the daemon.
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
