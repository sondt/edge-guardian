// Package app assembles the components and runs the daemon loop.
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

// Deps gathers all of App's dependencies; allows injecting fakes in tests.
type Deps struct {
	Detectors []*Detector // detection sources (http, sshd, ...)
	Paths     []string    // union of log files to tail (for the tailer)
	Allow     *allow.List
	State     *state.Store
	Enforcer  enforce.Enforcer
	Notifier  notify.Notifier
	GeoIP     GeoIP

	BanDuration time.Duration // flat ban (when escalation is empty)

	// Escalation: ban duration that escalates with the number of repeat offenses (empty = flat ban).
	// EscalationMemory: how long to keep offender history after a ban expires (to count repeats).
	Escalation       []time.Duration
	EscalationMemory time.Duration

	DryRun bool
	Logger *slog.Logger

	// Events receives detection events (for the dashboard); nil => ignored.
	Events EventSink

	// Errors receives 4xx/5xx requests seen in the access log (for the /errors page);
	// nil => ignored.
	Errors ErrorSink

	// Health branch (optional). Health == nil => fully disabled. Reads EVERY log line to
	// aggregate per-site counters and alert on status — does NOT ban IPs.
	Health            *health.Health
	HealthAlerter     *health.Alerter   // nil => do not send alerts
	HealthParser      *parse.LineParser // parses host/status/latency for health
	HealthWindow      int               // window (minutes) for the dashboard snapshot
	HealthAlertWindow int               // window (minutes) for alert evaluation

	// Now allows controlling time in tests; nil => time.Now.
	Now func() time.Time
}

// GeoIP resolves a source IP → location/network. *geoip.Resolver and geoip.Nop satisfy it.
type GeoIP interface {
	Lookup(ip string) geoip.Result
}

// EventSink receives each ban/would-ban event for realtime display (dashboard).
// Split into an interface so the hot path does not depend hard on the web package.
type EventSink interface {
	Push(at time.Time, ip, detector, action, country, asn string)
}

// noopSink ignores all events.
type noopSink struct{}

func (noopSink) Push(time.Time, string, string, string, string, string) {}

// ErrorEvent is one 4xx/5xx request captured for the dashboard's /errors page, enriched
// with the user-agent and GeoIP origin at capture time.
type ErrorEvent struct {
	At       time.Time
	Host     string
	IP       string
	Path     string
	UA       string
	Country  string
	ASN      string
	Location string
	Status   int
}

// ErrorSink receives each error request (4xx/5xx) for the dashboard's /errors page.
type ErrorSink interface {
	PushError(ErrorEvent)
}

// noopErrorSink ignores all error requests.
type noopErrorSink struct{}

func (noopErrorSink) PushError(ErrorEvent) {}

// Service is a background process that runs alongside the daemon (control socket, dashboard...).
type Service interface {
	// Start runs until ctx is cancelled; returns an error if it fails to start.
	Start(ctx context.Context) error
	// Name is used for logging.
	Name() string
}

// App is the assembled daemon.
type App struct {
	d   Deps
	now func() time.Time
}

// New creates an App from prepared Deps.
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
	if d.Errors == nil {
		d.Errors = noopErrorSink{}
	}
	return &App{d: d, now: now}
}

const (
	saveInterval  = 30 * time.Second
	pruneInterval = 5 * time.Minute
	alertInterval = 1 * time.Minute // health alert evaluation cycle
)

// Paths returns the log files the daemon needs to tail (union across detectors).
func (a *App) Paths() []string { return a.d.Paths }

// Run restores state into nftables, starts the background services (control socket,
// dashboard...), then consumes logs until ctx is cancelled.
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

// Restore reloads the still-valid IPs from state into nftables (the set is empty after a
// reboot). Skipped on dry-run. Per-IP errors are logged and do not halt the process.
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
		if a.d.Allow.Contains(addr) {
			a.d.Logger.Info("restore: skip allowlisted ip", "ip", e.IP)
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
