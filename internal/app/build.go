package app

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/sondt/edge-guardian/internal/allow"
	"github.com/sondt/edge-guardian/internal/blocklist"
	"github.com/sondt/edge-guardian/internal/config"
	"github.com/sondt/edge-guardian/internal/control"
	"github.com/sondt/edge-guardian/internal/detect"
	"github.com/sondt/edge-guardian/internal/enforce"
	"github.com/sondt/edge-guardian/internal/geoip"
	"github.com/sondt/edge-guardian/internal/health"
	"github.com/sondt/edge-guardian/internal/notify"
	"github.com/sondt/edge-guardian/internal/parse"
	"github.com/sondt/edge-guardian/internal/state"
	"github.com/sondt/edge-guardian/internal/web"
)

// eventRetention is how long the dashboard keeps detection events in RAM.
const eventRetention = 24 * time.Hour

// Components là các thành phần đã khởi tạo từ config, kèm hàm dọn dẹp.
type Components struct {
	App      *App
	Services []Service
	Cleanup  func()
}

// Build khởi tạo mọi thành phần từ config. Caller chịu trách nhiệm gọi Cleanup.
// now lấy mặc định time.Now bên trong New.
func Build(cfg config.Config, logger *slog.Logger) (*Components, error) {
	detectors, paths, err := buildDetectors(cfg)
	if err != nil {
		return nil, err
	}
	prefixes, err := cfg.Whitelist()
	if err != nil {
		return nil, err
	}
	banDur, err := cfg.BanDuration()
	if err != nil {
		return nil, err
	}
	escalation, err := cfg.Ban.EscalationDurations()
	if err != nil {
		return nil, err
	}
	escMemory, err := cfg.Ban.EscalationMemoryDuration()
	if err != nil {
		return nil, err
	}

	st, err := state.Load(cfg.State.Path, time.Now(), escMemory)
	if err != nil {
		return nil, err
	}

	// GeoIP is best-effort: a bad/missing DB must NOT block the daemon. On error we log
	// and continue with whatever readers opened (the resolver is nil-safe).
	geo, err := geoip.New(cfg.GeoIP.CityDB, cfg.GeoIP.ASNDB)
	if err != nil {
		logger.Warn("GeoIP: open DB failed → that part is no-op", "err", err,
			"city_db", cfg.GeoIP.CityDB, "asn_db", cfg.GeoIP.ASNDB)
	}
	if cityN, asnN := geo.Stats(); cityN > 0 || asnN > 0 {
		logger.Info("GeoIP loaded", "city_readers", cityN, "asn_readers", asnN)
	}

	enf, err := enforce.New(enforce.Config{
		Table:      cfg.Ban.NftTable,
		SetV4:      cfg.Ban.NftSetV4,
		SetV6:      cfg.Ban.NftSetV6,
		BlockSetV4: "blockset4",
		BlockSetV6: "blockset6",
	})
	if err != nil {
		geo.Close()
		return nil, fmt.Errorf("init enforcer: %w", err)
	}

	var channels []notify.Notifier
	if cfg.Telegram.Enabled {
		channels = append(channels, notify.NewTelegram(cfg.Telegram.BotToken, cfg.Telegram.ChatID))
	}
	if cfg.Email.Enabled {
		channels = append(channels, notify.NewResend(cfg.Email.ResendAPIKey, cfg.Email.From, cfg.Email.To))
	}
	notifier := notify.Multi(channels...)

	// The dashboard's event ring buffer (if enabled) doubles as the pipeline's event
	// sink, so build it before Deps.
	var store *web.Store
	d := Deps{
		Detectors:        detectors,
		Paths:            paths,
		Allow:            allow.New(prefixes),
		State:            st,
		Enforcer:         enf,
		Notifier:         notifier,
		GeoIP:            geo,
		BanDuration:      banDur,
		Escalation:       escalation,
		EscalationMemory: escMemory,
		DryRun:           cfg.Detection.DryRun,
		Logger:           logger,
	}
	if cfg.Dashboard.Enabled {
		store = web.NewStore(eventRetention)
		d.Events = webSink{store: store}
		maybeSeedDemo(store, time.Now()) // no-op unless EG_DEMO_SEED=1
	}

	// Health branch (optional) — reads every log line to aggregate per-site counters and
	// alert on degraded/down. Shares the access log + parser with detection.
	var healthSvc *health.Health
	if cfg.Health.Enabled {
		hp, err := parse.NewLineParser(cfg.Log.LineRegex)
		if err != nil {
			geo.Close()
			_ = enf.Close()
			return nil, fmt.Errorf("health line_regex: %w", err)
		}
		th := health.Thresholds{Err5xxRatio: cfg.Health.ErrRatio(), P95Sec: cfg.Health.P95Sec()}
		healthSvc = health.New(health.Config{
			WindowMins: cfg.Health.WindowMins,
			Sites:      cfg.Health.Sites,
			Thresholds: th,
		})
		d.Health = healthSvc
		d.HealthAlerter = health.NewAlerter(health.AlertConfig{
			Thresholds: th,
			Sustained:  cfg.Health.Sustained(),
			Cooldown:   cfg.Health.Cooldown(),
		})
		d.HealthParser = hp
		d.HealthWindow = cfg.Health.WindowMins
		d.HealthAlertWindow = cfg.Health.SustainedMins
		if maybeSeedHealthDemo(healthSvc) {
			logger.Info("health: seeded demo sites")
		}
	}

	application := New(d)

	var services []Service
	if cfg.Control.Enabled {
		services = append(services, control.NewServer(cfg.Control.SocketPath, application, logger))
	}
	if cfg.Dashboard.Enabled {
		data := dashboardData{
			state: st, geo: geo, app: application, now: application.now,
			health: healthSvc, healthWindow: cfg.Health.WindowMins,
		}
		services = append(services, web.New(web.Config{
			Enabled:          cfg.Dashboard.Enabled,
			Listen:           cfg.Dashboard.Listen,
			Username:         cfg.Dashboard.Username,
			PasswordHash:     cfg.Dashboard.PasswordHash,
			HealthWindowMins: healthWindowMins(cfg),
		}, data, store))
	}
	if cfg.Blocklist.Enabled {
		services = append(services, blocklist.NewImporter(
			cfg.Blocklist.Sources, allow.New(prefixes), enf,
			cfg.Blocklist.RefreshInterval(), logger))
	}

	cleanup := func() {
		_ = enf.Close()
		_ = geo.Close()
		if err := st.Save(); err != nil {
			logger.Error("save state on cleanup", "err", err)
		}
	}

	return &Components{App: application, Services: services, Cleanup: cleanup}, nil
}

// buildDetectors constructs the enabled detection sources and the union of log paths
// to tail. HTTP scanner is always on; SSH brute-force is opt-in via [sshd].
func buildDetectors(cfg config.Config) ([]*Detector, []string, error) {
	var dets []*Detector
	var paths []string

	// HTTP scanner — nginx access log + bad-URI patterns.
	parser, err := parse.NewLineParser(cfg.Log.LineRegex)
	if err != nil {
		return nil, nil, err
	}
	matcher, err := detect.NewMatcher(cfg.Detection.BadURIPatterns)
	if err != nil {
		return nil, nil, err
	}
	dets = append(dets, &Detector{
		Name:   "http",
		Window: detect.Hits(cfg.Detection.Threshold, cfg.WindowDuration()),
		Inspect: func(line string) (ip, sub, reason string, ok bool) {
			ev, matched := parser.Parse(line)
			if !matched || !matcher.IsBad(ev.URI) {
				return "", "", "", false
			}
			return ev.IP, "", ev.URI, true
		},
	})
	paths = append(paths, cfg.Log.Paths...)

	// Exploit signatures — same nginx access log, but matched against attack payloads
	// (SQLi / path-traversal / RCE-probe / Log4Shell) in the URI. Opt-in via [exploit]:
	// higher false-positive risk than path scanning, so it ships off + threshold 2.
	if cfg.Exploit.Enabled {
		exMatcher, err := detect.NewMatcher(cfg.Exploit.Patterns)
		if err != nil {
			return nil, nil, err
		}
		dets = append(dets, &Detector{
			Name:   "exploit",
			Window: detect.Hits(cfg.Exploit.Threshold, cfg.Exploit.WindowDuration()),
			Inspect: func(line string) (ip, sub, reason string, ok bool) {
				ev, matched := parser.Parse(line)
				if !matched || !exMatcher.IsBad(ev.URI) {
					return "", "", "", false
				}
				return ev.IP, "", "exploit signature: " + ev.URI, true
			},
		})
		paths = append(paths, cfg.Log.Paths...)
	}

	// Bad-bot — same access log, matched against the User-Agent field (vuln scanners,
	// pentest tools, abusive automation). Opt-in via [badbot]; requires the line_regex to
	// capture (?P<ua>...) — config validation enforces that.
	if cfg.BadBot.Enabled {
		if !parser.HasUA() {
			return nil, nil, fmt.Errorf("badbot enabled but line_regex has no (?P<ua>...) group")
		}
		botMatcher, err := detect.NewMatcher(cfg.BadBot.Patterns)
		if err != nil {
			return nil, nil, err
		}
		dets = append(dets, &Detector{
			Name:   "badbot",
			Window: detect.Hits(cfg.BadBot.Threshold, cfg.BadBot.WindowDuration()),
			Inspect: func(line string) (ip, sub, reason string, ok bool) {
				ev, matched := parser.Parse(line)
				if !matched || ev.UA == "" || !botMatcher.IsBad(ev.UA) {
					return "", "", "", false
				}
				return ev.IP, "", "bad bot UA: " + ev.UA, true
			},
		})
		paths = append(paths, cfg.Log.Paths...)
	}

	// Rate abuse / DoS-lite — count EVERY request per IP (no signature) and ban an IP
	// that floods past the threshold. Opt-in via [ratelimit]; highest false-positive risk
	// of all detectors (a proxy/CDN/monitor behind one IP will trip it), so it ships off
	// with a high threshold and the allowlist is essential.
	if cfg.RateLimit.Enabled {
		reason := fmt.Sprintf("rate abuse (>%d req / %ds)", cfg.RateLimit.Threshold, cfg.RateLimit.WindowSecs)
		dets = append(dets, &Detector{
			Name:   "ratelimit",
			Window: detect.Hits(cfg.RateLimit.Threshold, cfg.RateLimit.WindowDuration()),
			Inspect: func(line string) (ip, sub, reason2 string, ok bool) {
				ev, matched := parser.Parse(line)
				if !matched {
					return "", "", "", false
				}
				return ev.IP, "", reason, true
			},
		})
		paths = append(paths, cfg.Log.Paths...)
	}

	// SSH brute-force — auth.log / journald sshd failed logins.
	if cfg.SSHD.Enabled {
		sp := parse.NewSSHParser()
		dets = append(dets, &Detector{
			Name:   "sshd",
			Window: detect.Hits(cfg.SSHD.Threshold, cfg.SSHD.WindowDuration()),
			Inspect: func(line string) (ip, sub, reason string, ok bool) {
				ip, reason, ok = sp.Parse(line)
				return ip, "", reason, ok
			},
		})
		paths = append(paths, cfg.SSHD.Paths...)
	}

	// Honeypot port — any packet to a decoy port (nft LOG prefix EDGEGUARD-HONEYPOT) =
	// instant ban (threshold 1). Highest-quality signal: no legit reason to touch it.
	if cfg.Honeypot.Enabled {
		hp := parse.NewNetfilterParser(cfg.Honeypot.LogPrefix)
		dets = append(dets, &Detector{
			Name:   "honeypot",
			Window: detect.Hits(1, time.Minute),
			Inspect: func(line string) (ip, sub, reason string, ok bool) {
				ev, matched := hp.Parse(line)
				if !matched {
					return "", "", "", false
				}
				return ev.IP, "", "honeypot port :" + ev.Port, true
			},
		})
		paths = append(paths, cfg.Honeypot.Paths...)
	}

	// Port scan — count DISTINCT destination ports per IP (nft LOG prefix EDGEGUARD-SCAN).
	if cfg.PortScan.Enabled {
		ps := parse.NewNetfilterParser(cfg.PortScan.LogPrefix)
		dets = append(dets, &Detector{
			Name:   "portscan",
			Window: detect.NewDistinct(cfg.PortScan.Threshold, cfg.PortScan.WindowDuration()),
			Inspect: func(line string) (ip, sub, reason string, ok bool) {
				ev, matched := ps.Parse(line)
				if !matched {
					return "", "", "", false
				}
				return ev.IP, ev.Port, "port scan (distinct ports)", true
			},
		})
		paths = append(paths, cfg.PortScan.Paths...)
	}

	return dets, dedupeStrings(paths), nil
}

// healthWindowMins returns the health snapshot window for the dashboard, or 0 when the
// health branch is off (which hides the "Sites" nav link).
func healthWindowMins(cfg config.Config) int {
	if !cfg.Health.Enabled {
		return 0
	}
	return cfg.Health.WindowMins
}

// dedupeStrings returns the input with duplicates removed, order preserved — so a path
// shared by two detectors is tailed only once.
func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
