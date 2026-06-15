// Package config reads and validates edge-guardian's TOML configuration file.
package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/sondt/edge-guardian/internal/parse"
)

// Config is the daemon's complete configuration, mapped from the TOML file.
type Config struct {
	Log       LogConfig       `toml:"log"`
	Detection DetectionConfig `toml:"detection"`
	Exploit   ExploitConfig   `toml:"exploit"`
	BadBot    BadBotConfig    `toml:"badbot"`
	RateLimit RateLimitConfig `toml:"ratelimit"`
	Health    HealthConfig    `toml:"health"`
	Ban       BanConfig       `toml:"ban"`
	Telegram  TelegramConfig  `toml:"telegram"`
	Email     EmailConfig     `toml:"email"`
	GeoIP     GeoIPConfig     `toml:"geoip"`
	State     StateConfig     `toml:"state"`
	Control   ControlConfig   `toml:"control"`
	Dashboard DashboardConfig `toml:"dashboard"`
	SSHD      SSHDConfig      `toml:"sshd"`
	Honeypot  HoneypotConfig  `toml:"honeypot"`
	PortScan  PortScanConfig  `toml:"portscan"`
	Blocklist BlocklistConfig `toml:"blocklist"`
}

// BlocklistConfig — import public IP blocklists (FireHOL, Spamhaus...) loaded proactively
// into the nftables interval set.
type BlocklistConfig struct {
	Enabled      bool     `toml:"enabled"`
	Sources      []string `toml:"sources"`       // blocklist URLs
	RefreshHours int      `toml:"refresh_hours"` // refresh interval (hours)
}

// RefreshInterval returns the refresh interval as a time.Duration (defaults to 24h if <=0).
func (c BlocklistConfig) RefreshInterval() time.Duration {
	if c.RefreshHours <= 0 {
		return 24 * time.Hour
	}
	return time.Duration(c.RefreshHours) * time.Hour
}

// HoneypotConfig — catch packets hitting a decoy port (nft LOG prefix) → ban immediately (threshold 1).
type HoneypotConfig struct {
	Enabled   bool     `toml:"enabled"`
	Paths     []string `toml:"paths"`      // file holding kernel netfilter LOG (routed out by journald/rsyslog)
	LogPrefix string   `toml:"log_prefix"` // nft rule prefix, e.g. "EDGEGUARD-HONEYPOT"
}

// PortScanConfig — count distinct destination PORTs per IP (nft LOG prefix) → ban when over threshold.
type PortScanConfig struct {
	Enabled    bool     `toml:"enabled"`
	Paths      []string `toml:"paths"`
	LogPrefix  string   `toml:"log_prefix"` // e.g. "EDGEGUARD-SCAN"
	Threshold  int      `toml:"threshold"`  // number of distinct ports within the window
	WindowSecs int      `toml:"window_secs"`
}

// WindowDuration returns the port scan sliding window as a time.Duration.
func (c PortScanConfig) WindowDuration() time.Duration {
	return time.Duration(c.WindowSecs) * time.Second
}

// SSHDConfig controls SSH brute-force detection from auth.log/journald.
type SSHDConfig struct {
	Enabled    bool     `toml:"enabled"`
	Paths      []string `toml:"paths"`
	Threshold  int      `toml:"threshold"`
	WindowSecs int      `toml:"window_secs"`
}

// WindowDuration returns the sshd sliding window as a time.Duration.
func (c SSHDConfig) WindowDuration() time.Duration {
	return time.Duration(c.WindowSecs) * time.Second
}

// ControlConfig configures the unix control socket — lets `edge-guardian unban` act
// directly on the running daemon (updating in-memory state + nftables).
type ControlConfig struct {
	Enabled    bool   `toml:"enabled"`
	SocketPath string `toml:"socket_path"`
}

// DashboardConfig configures the local web dashboard (optional). Binds to localhost by default.
type DashboardConfig struct {
	Enabled      bool   `toml:"enabled"`
	Listen       string `toml:"listen"`
	Username     string `toml:"username"`
	PasswordHash string `toml:"password_hash"` // bcrypt
}

// LogConfig declares the log sources and how to extract from them.
type LogConfig struct {
	Paths     []string `toml:"paths"`
	LineRegex string   `toml:"line_regex"`
}

// DetectionConfig controls HTTP scanner detection.
type DetectionConfig struct {
	BadURIPatterns []string `toml:"bad_uri_patterns"`
	Threshold      int      `toml:"threshold"`
	WindowSecs     int      `toml:"window_secs"`
	DryRun         bool     `toml:"dry_run"`
}

// ExploitConfig controls exploit-pattern detection (SQLi/path-traversal/RCE/Log4Shell)
// on access-log URIs (same source as the HTTP scanner). DISABLED BY DEFAULT: it carries a
// higher false-positive risk than the path scanner, so run it in dry-run to observe and tune
// before enabling.
type ExploitConfig struct {
	Enabled    bool     `toml:"enabled"`
	Patterns   []string `toml:"patterns"`  // regex (auto case-insensitive) applied to the URI
	Threshold  int      `toml:"threshold"` // number of matches within the window to ban
	WindowSecs int      `toml:"window_secs"`
}

// WindowDuration returns the exploit sliding window as a time.Duration.
func (c ExploitConfig) WindowDuration() time.Duration {
	return time.Duration(c.WindowSecs) * time.Second
}

// DefaultExploitPatterns returns the default exploit signature set (anchored to reduce false
// positives). Applied to the URI (including the query string). Covers common URL-encoded forms too.
func DefaultExploitPatterns() []string {
	return []string{
		// Path traversal / LFI
		`(\.\.(/|\\|%2f|%5c)){2,}`,
		`(/|%2f)(etc/passwd|etc/shadow|proc/self/environ|windows/win\.ini|boot\.ini)`,
		// SQL injection
		`union(\s|\+|%20)+select`,
		`\bor(\s|\+|%20)+1(\s|\+|%20)*=(\s|\+|%20)*1\b`,
		`'(\s|\+|%20)*or(\s|\+|%20)*'?1'?`,
		`\binformation_schema\b`,
		`\b(sleep|benchmark|pg_sleep|waitfor(\s|\+|%20)+delay)(\s|\+|%20)*\(`,
		`\binto(\s|\+|%20)+(out|dump)file\b`,
		// Command injection / RCE
		`[;|` + "`" + `]\s*(cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python|perl)\b`,
		`\$\((.*)\)`,
		`%0a(cat|ls|id|whoami|wget|curl)`,
		`\b(wget|curl)(\s|\+|%20)+https?://`,
		`\b(system|passthru|shell_exec|proc_open|popen|exec)(\s|%20)*\(`,
		// PHP wrappers / RFI
		`(php|data|expect|phar|file)://`,
		// Log4Shell / JNDI
		`\$\{(jndi|env|sys|lower|upper|date):`,
		// Obvious XSS probes
		`(<|%3c)script`,
		`\bon(error|load|mouseover)(\s|%20)*=`,
		`javascript:`,
	}
}

// BadBotConfig controls bad-bot detection by User-Agent (vuln scanner / attack tool
// / abusive automation library). Reads the same access log as the HTTP scanner but matches the
// user-agent field instead of the URI, so line_regex MUST have a (?P<ua>...) group.
type BadBotConfig struct {
	Enabled    bool     `toml:"enabled"`
	Patterns   []string `toml:"patterns"`  // regex (auto case-insensitive) applied to the User-Agent
	Threshold  int      `toml:"threshold"` // number of matches within the window to ban
	WindowSecs int      `toml:"window_secs"`
}

// WindowDuration returns the bad-bot sliding window as a time.Duration.
func (c BadBotConfig) WindowDuration() time.Duration {
	return time.Duration(c.WindowSecs) * time.Second
}

// DefaultBadBotPatterns returns the default User-Agent signature set: pentest/scanner tools
// and automated bots with NO legitimate reason to reach a normal web server. Word-anchored
// (\b) to reduce false positives against real browser UAs.
func DefaultBadBotPatterns() []string {
	return []string{
		// Vulnerability / pentest scanners
		`\bsqlmap\b`,
		`\bnikto\b`,
		`\b(acunetix|netsparker|nessus|openvas|qualys|whatweb|wpscan|joomscan)\b`,
		`\b(nuclei|httpx|dirbuster|gobuster|feroxbuster|ffuf|dirsearch|wfuzz)\b`,
		`\b(masscan|zgrab|zmap|nmap|nuclei|xray|hydra)\b`,
		// Mass scrapers / abusive crawlers often tied to exploitation
		`\b(semrushbot|ahrefsbot|mj12bot|dotbot|petalbot|blexbot|seznambot)\b`,
		// Generic automation libraries (higher FP risk — trim if you have legitimate clients)
		`\b(python-requests|go-http-client|libwww-perl|winhttp|java)/`,
		`\b(curl|wget)/`,
		`\b(scrapy|httpunit|okhttp|aiohttp|node-fetch|axios)\b`,
	}
}

// RateLimitConfig controls rate-abuse / DoS-lite detection: an IP that exceeds the TOTAL
// request count within the window (regardless of content). NO signature like the other
// detectors → this is the HIGHEST false-positive-risk source: proxies/CDNs/monitoring that
// aggregate many clients behind one IP will exceed the threshold. Disabled by default, high
// threshold, MUST allowlist infrastructure.
type RateLimitConfig struct {
	Enabled    bool `toml:"enabled"`
	Threshold  int  `toml:"threshold"`   // number of requests within the window to ban
	WindowSecs int  `toml:"window_secs"` // window width (seconds)
}

// WindowDuration returns the rate-limit sliding window as a time.Duration.
func (c RateLimitConfig) WindowDuration() time.Duration {
	return time.Duration(c.WindowSecs) * time.Second
}

// HealthConfig controls the "edge health" branch: read EVERY access-log line, aggregate
// per-site counters (status mix, error rate, req/s, latency) and alert when a site is
// degraded/down. Does NOT ban IPs. Requires logs with host/status (+ request_time for latency) —
// nginx JSON format recommended (see docs/10).
type HealthConfig struct {
	Enabled       bool     `toml:"enabled"`
	Sites         []string `toml:"sites"`          // hosts to monitor; empty = every host in the log
	WindowMins    int      `toml:"window_mins"`    // number of minute buckets kept in RAM
	ErrRatioPct   float64  `toml:"err_ratio_pct"`  // 5xx ratio alert threshold (e.g. 5)
	LatencyP95Ms  int      `toml:"latency_p95_ms"` // p95 threshold (ms); 0 = ignore latency
	SustainedMins int      `toml:"sustained_mins"` // how long the condition must hold before alerting
	CooldownMins  int      `toml:"cooldown_mins"`  // stay silent after alerting

	// DiscoverNginx, when unset or true, lists/counts the sites nginx serves via `nginx -T`
	// (used only when `sites` is empty). Set false to keep the "track any host" behavior.
	DiscoverNginx  *bool    `toml:"discover_nginx"`
	NginxConfGlobs []string `toml:"nginx_conf_globs"` // fallback config globs if `nginx -T` is unavailable
}

// DiscoverSites reports whether to auto-discover nginx server_names (default true).
func (c HealthConfig) DiscoverSites() bool {
	return c.DiscoverNginx == nil || *c.DiscoverNginx
}

// Helpers converting config thresholds into the form the health package uses (ratio 0..1, seconds).
func (c HealthConfig) ErrRatio() float64 { return c.ErrRatioPct / 100 }
func (c HealthConfig) P95Sec() float64   { return float64(c.LatencyP95Ms) / 1000 }
func (c HealthConfig) Sustained() time.Duration {
	return time.Duration(c.SustainedMins) * time.Minute
}
func (c HealthConfig) Cooldown() time.Duration {
	return time.Duration(c.CooldownMins) * time.Minute
}

// BanConfig controls nftables blocking.
type BanConfig struct {
	Duration  string   `toml:"duration"`
	Whitelist []string `toml:"whitelist"`
	NftTable  string   `toml:"nft_table"`
	NftSetV4  string   `toml:"nft_set_v4"`
	NftSetV6  string   `toml:"nft_set_v6"`

	// Escalation: ban durations that escalate with the number of repeat offenses. Empty = flat
	// ban (always use Duration). The Nth repeat offense uses Escalation[min(N, len-1)]. The value
	// "permanent" = a near-permanent ban. E.g. ["24h","168h","720h","permanent"].
	Escalation []string `toml:"escalation"`
	// EscalationMemory: how long to keep offender history (ban count) after a ban expires,
	// to count repeat offenses. Defaults to 720h (30 days) when escalation is enabled.
	EscalationMemory string `toml:"escalation_memory"`
}

// permanentDuration is the sentinel for a "permanent" ban (100 years — beyond any real lifetime).
const permanentDuration = 100 * 365 * 24 * time.Hour

// EscalationDurations parses the escalation list into []time.Duration ("permanent" →
// permanentDuration). Empty → nil (flat ban).
func (c BanConfig) EscalationDurations() ([]time.Duration, error) {
	if len(c.Escalation) == 0 {
		return nil, nil
	}
	out := make([]time.Duration, 0, len(c.Escalation))
	for _, s := range c.Escalation {
		if strings.EqualFold(strings.TrimSpace(s), "permanent") {
			out = append(out, permanentDuration)
			continue
		}
		d, err := parseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("ban.escalation %q: %w", s, err)
		}
		out = append(out, d)
	}
	return out, nil
}

// EscalationMemoryDuration returns the memory window (defaults to 30 days when escalation is
// enabled, 0 when disabled).
func (c BanConfig) EscalationMemoryDuration() (time.Duration, error) {
	if len(c.Escalation) == 0 {
		return 0, nil
	}
	if strings.TrimSpace(c.EscalationMemory) == "" {
		return 30 * 24 * time.Hour, nil
	}
	return parseDuration(c.EscalationMemory)
}

// TelegramConfig configures the Telegram notification channel.
type TelegramConfig struct {
	Enabled  bool   `toml:"enabled"`
	BotToken string `toml:"bot_token"`
	ChatID   string `toml:"chat_id"`
}

// EmailConfig configures the email notification channel via Resend (https://resend.com).
type EmailConfig struct {
	Enabled      bool     `toml:"enabled"`
	ResendAPIKey string   `toml:"resend_api_key"`
	From         string   `toml:"from"` // sender address (domain verified at Resend)
	To           []string `toml:"to"`   // recipient list
}

// GeoIPConfig (optional) points to OFFLINE MMDB files to resolve IP → location/network. Each
// value is 1+ comma-separated paths (sapics's City set splits IPv4/IPv6 separately, so point
// at both). Empty = disabled. Reads maxminddb directly, so it works with BOTH the FREE sapics/
// ip-location-db files and standard MaxMind/DB-IP — see internal/geoip.
type GeoIPConfig struct {
	CityDB string `toml:"city_db"` // location DB (country/region/city/coordinates)
	ASNDB  string `toml:"asn_db"`  // network DB (ASN + ISP/organization name)
}

// StateConfig is the location of the JSON state file.
type StateConfig struct {
	Path string `toml:"path"`
}

// Defaults are the safe default values applied before reading the file.
func Defaults() Config {
	return Config{
		Log: LogConfig{
			// Combined log format. The trailing group (status, bytes, referer, UA) is
			// optional so lines without it (or non-combined formats) still match for
			// ip+uri. status/bytes feed the health branch; ua feeds bad-bot. For full
			// health (host + latency) switch nginx to the JSON format — see docs/10.
			LineRegex: `^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?:\S+) (?P<uri>\S+)[^"]*" (?:(?P<status>\d+) (?P<bytes>\S+) "[^"]*" "(?P<ua>[^"]*)")?`,
		},
		Detection: DetectionConfig{
			BadURIPatterns: []string{`\.(php|cgi|asp|aspx|jsp|env|git|sql|bak)(\?|/|$)`},
			Threshold:      1,
			WindowSecs:     60,
		},
		Exploit: ExploitConfig{
			Enabled:    false,
			Patterns:   DefaultExploitPatterns(),
			Threshold:  2,
			WindowSecs: 60,
		},
		BadBot: BadBotConfig{
			Enabled:    false,
			Patterns:   DefaultBadBotPatterns(),
			Threshold:  1,
			WindowSecs: 60,
		},
		RateLimit: RateLimitConfig{
			Enabled:    false,
			Threshold:  300, // ~30 req/s sustained over 10s — clearly non-human
			WindowSecs: 10,
		},
		Health: HealthConfig{
			Enabled:       false,
			WindowMins:    180,
			ErrRatioPct:   5,
			LatencyP95Ms:  2000,
			SustainedMins: 5,
			CooldownMins:  30,
		},
		Ban: BanConfig{
			Duration:  "168h",
			Whitelist: []string{"127.0.0.0/8", "::1/128"},
			NftTable:  "edge_guardian",
			NftSetV4:  "blocklist4",
			NftSetV6:  "blocklist6",
		},
		State: StateConfig{Path: "/var/lib/edge-guardian/state.json"},
		Control: ControlConfig{
			Enabled:    true,
			SocketPath: "/run/edge-guardian.sock",
		},
		Dashboard: DashboardConfig{
			Enabled: false,
			Listen:  "127.0.0.1:8787",
		},
		SSHD: SSHDConfig{
			Enabled:    false,
			Paths:      []string{"/var/log/auth.log"},
			Threshold:  5,
			WindowSecs: 60,
		},
		Honeypot: HoneypotConfig{
			Enabled:   false,
			Paths:     []string{"/var/log/edge-guardian/netfilter.log"},
			LogPrefix: "EDGEGUARD-HONEYPOT",
		},
		PortScan: PortScanConfig{
			Enabled:    false,
			Paths:      []string{"/var/log/edge-guardian/netfilter.log"},
			LogPrefix:  "EDGEGUARD-SCAN",
			Threshold:  10,
			WindowSecs: 60,
		},
		Blocklist: BlocklistConfig{
			Enabled: false,
			Sources: []string{
				"https://iplists.firehol.org/files/firehol_level1.netset",
				"https://www.spamhaus.org/drop/drop.txt",
			},
			RefreshHours: 24,
		},
	}
}

// Load reads the TOML file at path, overlays it on the defaults, then validates.
func Load(path string) (Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config %q: %w", path, err)
	}
	return cfg, nil
}

// BanDuration returns the ban duration parsed from Ban.Duration.
func (c Config) BanDuration() (time.Duration, error) {
	return parseDuration(c.Ban.Duration)
}

// WindowDuration returns the sliding window as a time.Duration.
func (c Config) WindowDuration() time.Duration {
	return time.Duration(c.Detection.WindowSecs) * time.Second
}

// Whitelist returns the parsed prefix list (already validated in Validate).
func (c Config) Whitelist() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.Ban.Whitelist))
	for _, s := range c.Ban.Whitelist {
		p, err := parsePrefixOrAddr(s)
		if err != nil {
			return nil, fmt.Errorf("whitelist entry %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// parsePrefixOrAddr accepts either CIDR notation ("10.0.0.0/8", "203.0.113.0/24") or a
// bare single IP ("203.0.113.7", "::1"). A bare IP is treated as a single-host prefix
// (/32 for IPv4, /128 for IPv6), so operators can allowlist one address without having
// to remember the /32 suffix.
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not a valid IP or CIDR")
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// Validate checks the configuration at the system boundary; fails fast with a clear message.
func (c Config) Validate() error {
	if len(c.Log.Paths) == 0 {
		return fmt.Errorf("log.paths must list at least one log file")
	}
	if err := validateLineRegex(c.Log.LineRegex); err != nil {
		return err
	}
	if len(c.Detection.BadURIPatterns) == 0 {
		return fmt.Errorf("detection.bad_uri_patterns must not be empty")
	}
	for _, p := range c.Detection.BadURIPatterns {
		// Match the exact form the detector compiles (case-insensitive) so validation
		// reflects runtime behavior — see detect.NewMatcher.
		if _, err := regexp.Compile("(?i)" + p); err != nil {
			return fmt.Errorf("detection.bad_uri_patterns: invalid regex %q: %w", p, err)
		}
	}
	if c.Detection.Threshold < 1 {
		return fmt.Errorf("detection.threshold must be >= 1, got %d", c.Detection.Threshold)
	}
	if c.Detection.WindowSecs < 1 {
		return fmt.Errorf("detection.window_secs must be >= 1, got %d", c.Detection.WindowSecs)
	}
	if err := c.validateExploit(); err != nil {
		return err
	}
	if err := c.validateBadBot(); err != nil {
		return err
	}
	if err := c.validateRateLimit(); err != nil {
		return err
	}
	if err := c.validateHealth(); err != nil {
		return err
	}
	if _, err := parseDuration(c.Ban.Duration); err != nil {
		return fmt.Errorf("ban.duration %q: %w", c.Ban.Duration, err)
	}
	if _, err := c.Ban.EscalationDurations(); err != nil {
		return err
	}
	if _, err := c.Ban.EscalationMemoryDuration(); err != nil {
		return fmt.Errorf("ban.escalation_memory %q: %w", c.Ban.EscalationMemory, err)
	}
	if _, err := c.Whitelist(); err != nil {
		return err
	}
	if c.Ban.NftTable == "" || c.Ban.NftSetV4 == "" || c.Ban.NftSetV6 == "" {
		return fmt.Errorf("ban.nft_table / nft_set_v4 / nft_set_v6 must not be empty")
	}
	if c.Telegram.Enabled {
		if c.Telegram.BotToken == "" || c.Telegram.ChatID == "" {
			return fmt.Errorf("telegram.enabled is true but bot_token/chat_id is empty")
		}
	}
	if c.Email.Enabled {
		if c.Email.ResendAPIKey == "" || c.Email.From == "" || len(c.Email.To) == 0 {
			return fmt.Errorf("email.enabled is true but resend_api_key/from/to is empty")
		}
	}
	if c.State.Path == "" {
		return fmt.Errorf("state.path must not be empty")
	}
	if c.Control.Enabled && c.Control.SocketPath == "" {
		return fmt.Errorf("control.enabled is true but socket_path is empty")
	}
	if err := c.validateDashboard(); err != nil {
		return err
	}
	if err := c.validateSSHD(); err != nil {
		return err
	}
	if c.Honeypot.Enabled {
		if len(c.Honeypot.Paths) == 0 {
			return fmt.Errorf("honeypot.enabled is true but paths is empty")
		}
		if c.Honeypot.LogPrefix == "" {
			return fmt.Errorf("honeypot.enabled is true but log_prefix is empty")
		}
	}
	if err := c.validatePortScan(); err != nil {
		return err
	}
	if c.Blocklist.Enabled && len(c.Blocklist.Sources) == 0 {
		return fmt.Errorf("blocklist.enabled is true but sources is empty")
	}
	return nil
}

func (c Config) validateExploit() error {
	if !c.Exploit.Enabled {
		return nil
	}
	if len(c.Exploit.Patterns) == 0 {
		return fmt.Errorf("exploit.enabled is true but patterns is empty")
	}
	for _, p := range c.Exploit.Patterns {
		// Mirror detect.NewMatcher (case-insensitive) so validation reflects runtime.
		if _, err := regexp.Compile("(?i)" + p); err != nil {
			return fmt.Errorf("exploit.patterns: invalid regex %q: %w", p, err)
		}
	}
	if c.Exploit.Threshold < 1 {
		return fmt.Errorf("exploit.threshold must be >= 1, got %d", c.Exploit.Threshold)
	}
	if c.Exploit.WindowSecs < 1 {
		return fmt.Errorf("exploit.window_secs must be >= 1, got %d", c.Exploit.WindowSecs)
	}
	return nil
}

func (c Config) validateBadBot() error {
	if !c.BadBot.Enabled {
		return nil
	}
	if len(c.BadBot.Patterns) == 0 {
		return fmt.Errorf("badbot.enabled is true but patterns is empty")
	}
	for _, p := range c.BadBot.Patterns {
		// Mirror detect.NewMatcher (case-insensitive) so validation reflects runtime.
		if _, err := regexp.Compile("(?i)" + p); err != nil {
			return fmt.Errorf("badbot.patterns: invalid regex %q: %w", p, err)
		}
	}
	if c.BadBot.Threshold < 1 {
		return fmt.Errorf("badbot.threshold must be >= 1, got %d", c.BadBot.Threshold)
	}
	if c.BadBot.WindowSecs < 1 {
		return fmt.Errorf("badbot.window_secs must be >= 1, got %d", c.BadBot.WindowSecs)
	}
	// bad-bot matches the user-agent, so the line_regex must capture it. Fail fast with a
	// clear message rather than silently never matching.
	p, err := parse.NewLineParser(c.Log.LineRegex)
	if err != nil {
		return err
	}
	if !p.HasUA() {
		return fmt.Errorf("badbot.enabled is true but log.line_regex has no (?P<ua>...) group — add it to capture the user-agent")
	}
	return nil
}

func (c Config) validateHealth() error {
	if !c.Health.Enabled {
		return nil
	}
	if c.Health.WindowMins < 1 {
		return fmt.Errorf("health.window_mins must be >= 1, got %d", c.Health.WindowMins)
	}
	if c.Health.ErrRatioPct < 0 || c.Health.ErrRatioPct > 100 {
		return fmt.Errorf("health.err_ratio_pct must be in [0,100], got %v", c.Health.ErrRatioPct)
	}
	if c.Health.LatencyP95Ms < 0 {
		return fmt.Errorf("health.latency_p95_ms must be >= 0, got %d", c.Health.LatencyP95Ms)
	}
	if c.Health.SustainedMins < 1 {
		return fmt.Errorf("health.sustained_mins must be >= 1, got %d", c.Health.SustainedMins)
	}
	if c.Health.CooldownMins < 0 {
		return fmt.Errorf("health.cooldown_mins must be >= 0, got %d", c.Health.CooldownMins)
	}
	return nil
}

func (c Config) validateRateLimit() error {
	if !c.RateLimit.Enabled {
		return nil
	}
	if c.RateLimit.Threshold < 1 {
		return fmt.Errorf("ratelimit.threshold must be >= 1, got %d", c.RateLimit.Threshold)
	}
	if c.RateLimit.WindowSecs < 1 {
		return fmt.Errorf("ratelimit.window_secs must be >= 1, got %d", c.RateLimit.WindowSecs)
	}
	return nil
}

func (c Config) validatePortScan() error {
	if !c.PortScan.Enabled {
		return nil
	}
	if len(c.PortScan.Paths) == 0 {
		return fmt.Errorf("portscan.enabled is true but paths is empty")
	}
	if c.PortScan.LogPrefix == "" {
		return fmt.Errorf("portscan.enabled is true but log_prefix is empty")
	}
	if c.PortScan.Threshold < 1 {
		return fmt.Errorf("portscan.threshold must be >= 1, got %d", c.PortScan.Threshold)
	}
	if c.PortScan.WindowSecs < 1 {
		return fmt.Errorf("portscan.window_secs must be >= 1, got %d", c.PortScan.WindowSecs)
	}
	return nil
}

func (c Config) validateSSHD() error {
	if !c.SSHD.Enabled {
		return nil
	}
	if len(c.SSHD.Paths) == 0 {
		return fmt.Errorf("sshd.enabled is true but paths is empty")
	}
	if c.SSHD.Threshold < 1 {
		return fmt.Errorf("sshd.threshold must be >= 1, got %d", c.SSHD.Threshold)
	}
	if c.SSHD.WindowSecs < 1 {
		return fmt.Errorf("sshd.window_secs must be >= 1, got %d", c.SSHD.WindowSecs)
	}
	return nil
}

func (c Config) validateDashboard() error {
	if !c.Dashboard.Enabled {
		return nil
	}
	if c.Dashboard.Listen == "" {
		return fmt.Errorf("dashboard.enabled is true but listen is empty")
	}
	if _, _, err := net.SplitHostPort(c.Dashboard.Listen); err != nil {
		return fmt.Errorf("dashboard.listen %q: %w", c.Dashboard.Listen, err)
	}
	if c.Dashboard.Username == "" {
		return fmt.Errorf("dashboard.enabled is true but username is empty")
	}
	// Require a bcrypt hash so a plaintext password can never sit in the config.
	if !strings.HasPrefix(c.Dashboard.PasswordHash, "$2") {
		return fmt.Errorf("dashboard.password_hash must be a bcrypt hash (starts with $2); generate one and never store plaintext")
	}
	return nil
}

func validateLineRegex(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("log.line_regex: invalid regex: %w", err)
	}
	names := re.SubexpNames()
	var hasIP, hasURI bool
	for _, n := range names {
		switch n {
		case "ip":
			hasIP = true
		case "uri":
			hasURI = true
		}
	}
	if !hasIP || !hasURI {
		return fmt.Errorf("log.line_regex must contain named groups (?P<ip>...) and (?P<uri>...)")
	}
	return nil
}

// parseDuration supports the nft timeout syntax: time.ParseDuration plus a "d" (day) suffix.
func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if n := len(s); s[n-1] == 'd' {
		var days int
		if _, err := fmt.Sscanf(s[:n-1], "%d", &days); err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid day duration %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	return d, nil
}
