// Package config đọc và validate file cấu hình TOML của edge-guardian.
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

// Config là toàn bộ cấu hình của daemon, ánh xạ từ file TOML.
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

// BlocklistConfig — import blocklist IP công khai (FireHOL, Spamhaus...) nạp proactively
// vào nftables interval set.
type BlocklistConfig struct {
	Enabled      bool     `toml:"enabled"`
	Sources      []string `toml:"sources"`       // URL các blocklist
	RefreshHours int      `toml:"refresh_hours"` // chu kỳ làm mới (giờ)
}

// RefreshInterval trả về chu kỳ làm mới dưới dạng time.Duration (mặc định 24h nếu <=0).
func (c BlocklistConfig) RefreshInterval() time.Duration {
	if c.RefreshHours <= 0 {
		return 24 * time.Hour
	}
	return time.Duration(c.RefreshHours) * time.Hour
}

// HoneypotConfig — bắt gói tới port mồi (nft LOG prefix) → ban ngay (threshold 1).
type HoneypotConfig struct {
	Enabled   bool     `toml:"enabled"`
	Paths     []string `toml:"paths"`      // file chứa kernel netfilter LOG (journald/rsyslog route ra)
	LogPrefix string   `toml:"log_prefix"` // prefix của rule nft, vd "EDGEGUARD-HONEYPOT"
}

// PortScanConfig — đếm số PORT đích distinct mỗi IP (nft LOG prefix) → ban khi vượt ngưỡng.
type PortScanConfig struct {
	Enabled    bool     `toml:"enabled"`
	Paths      []string `toml:"paths"`
	LogPrefix  string   `toml:"log_prefix"` // vd "EDGEGUARD-SCAN"
	Threshold  int      `toml:"threshold"`  // số port distinct trong cửa sổ
	WindowSecs int      `toml:"window_secs"`
}

// WindowDuration trả về cửa sổ trượt của port scan dưới dạng time.Duration.
func (c PortScanConfig) WindowDuration() time.Duration {
	return time.Duration(c.WindowSecs) * time.Second
}

// SSHDConfig điều khiển phát hiện SSH brute-force từ auth.log/journald.
type SSHDConfig struct {
	Enabled    bool     `toml:"enabled"`
	Paths      []string `toml:"paths"`
	Threshold  int      `toml:"threshold"`
	WindowSecs int      `toml:"window_secs"`
}

// WindowDuration trả về cửa sổ trượt của sshd dưới dạng time.Duration.
func (c SSHDConfig) WindowDuration() time.Duration {
	return time.Duration(c.WindowSecs) * time.Second
}

// ControlConfig cấu hình unix control socket — cho phép `edge-guardian unban` tác động
// trực tiếp lên daemon đang chạy (cập nhật state in-memory + nftables).
type ControlConfig struct {
	Enabled    bool   `toml:"enabled"`
	SocketPath string `toml:"socket_path"`
}

// DashboardConfig cấu hình web dashboard local (tùy chọn). Mặc định bind localhost.
type DashboardConfig struct {
	Enabled      bool   `toml:"enabled"`
	Listen       string `toml:"listen"`
	Username     string `toml:"username"`
	PasswordHash string `toml:"password_hash"` // bcrypt
}

// LogConfig khai báo nguồn log và cách trích xuất.
type LogConfig struct {
	Paths     []string `toml:"paths"`
	LineRegex string   `toml:"line_regex"`
}

// DetectionConfig điều khiển phát hiện HTTP scanner.
type DetectionConfig struct {
	BadURIPatterns []string `toml:"bad_uri_patterns"`
	Threshold      int      `toml:"threshold"`
	WindowSecs     int      `toml:"window_secs"`
	DryRun         bool     `toml:"dry_run"`
}

// ExploitConfig điều khiển phát hiện exploit pattern (SQLi/path-traversal/RCE/Log4Shell)
// trên URI của access log (cùng nguồn với HTTP scanner). MẶC ĐỊNH TẮT: rủi ro false
// positive cao hơn path scanner nên cần chạy dry-run quan sát + tinh chỉnh trước khi bật.
type ExploitConfig struct {
	Enabled    bool     `toml:"enabled"`
	Patterns   []string `toml:"patterns"`  // regex (tự case-insensitive) áp lên URI
	Threshold  int      `toml:"threshold"` // số lần khớp trong cửa sổ để ban
	WindowSecs int      `toml:"window_secs"`
}

// WindowDuration trả về cửa sổ trượt của exploit dưới dạng time.Duration.
func (c ExploitConfig) WindowDuration() time.Duration {
	return time.Duration(c.WindowSecs) * time.Second
}

// DefaultExploitPatterns trả về bộ chữ ký exploit mặc định (đã anchored để giảm false
// positive). Áp lên URI (gồm cả query string). Bao gồm cả dạng URL-encoded phổ biến.
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

// BadBotConfig điều khiển phát hiện bad-bot theo User-Agent (vuln scanner / attack tool
// / thư viện tự động lạm dụng). Đọc cùng access log với HTTP scanner nhưng khớp trường
// user-agent thay vì URI, nên line_regex PHẢI có group (?P<ua>...).
type BadBotConfig struct {
	Enabled    bool     `toml:"enabled"`
	Patterns   []string `toml:"patterns"`  // regex (tự case-insensitive) áp lên User-Agent
	Threshold  int      `toml:"threshold"` // số lần khớp trong cửa sổ để ban
	WindowSecs int      `toml:"window_secs"`
}

// WindowDuration trả về cửa sổ trượt của bad-bot dưới dạng time.Duration.
func (c BadBotConfig) WindowDuration() time.Duration {
	return time.Duration(c.WindowSecs) * time.Second
}

// DefaultBadBotPatterns trả về bộ chữ ký User-Agent mặc định: các công cụ pentest/scanner
// và bot tự động KHÔNG có lý do hợp lệ để chạm tới web server thường. Anchor theo từ
// (\b) để giảm false positive với UA trình duyệt thật.
func DefaultBadBotPatterns() []string {
	return []string{
		// Vulnerability / pentest scanners
		`\bsqlmap\b`,
		`\bnikto\b`,
		`\b(acunetix|netsparker|nessus|openvas|qualys|whatweb|wpscan|joomscan)\b`,
		`\b(nuclei|httpx|dirbuster|gobuster|feroxbuster|ffuf|dirsearch|wfuzz)\b`,
		`\b(masscan|zgrab|zmap|nmap|nuclei|xray|hydra)\b`,
		// Mass scrapers / abusive crawlers thường gắn với khai thác
		`\b(semrushbot|ahrefsbot|mj12bot|dotbot|petalbot|blexbot|seznambot)\b`,
		// Generic automation libraries (rủi ro FP cao hơn — tỉa nếu bạn có client hợp lệ)
		`\b(python-requests|go-http-client|libwww-perl|winhttp|java)/`,
		`\b(curl|wget)/`,
		`\b(scrapy|httpunit|okhttp|aiohttp|node-fetch|axios)\b`,
	}
}

// RateLimitConfig điều khiển phát hiện rate-abuse / DoS-lite: một IP vượt ngưỡng TỔNG
// số request trong cửa sổ (không quan tâm nội dung). KHÔNG signature như các detector
// khác → đây là nguồn rủi ro false-positive CAO NHẤT: proxy/CDN/monitoring gộp nhiều
// client sau một IP sẽ vượt ngưỡng. Mặc định TẮT, ngưỡng cao, BẮT BUỘC allowlist hạ tầng.
type RateLimitConfig struct {
	Enabled    bool `toml:"enabled"`
	Threshold  int  `toml:"threshold"`   // số request trong cửa sổ để ban
	WindowSecs int  `toml:"window_secs"` // độ rộng cửa sổ (giây)
}

// WindowDuration trả về cửa sổ trượt của rate-limit dưới dạng time.Duration.
func (c RateLimitConfig) WindowDuration() time.Duration {
	return time.Duration(c.WindowSecs) * time.Second
}

// HealthConfig điều khiển nhánh "sức khỏe biên": đọc MỌI dòng access log, tổng hợp
// counter per-site (status mix, error rate, req/s, latency) và cảnh báo khi site
// degraded/down. KHÔNG ban IP. Cần log có host/status (+ request_time cho latency) —
// khuyến nghị nginx JSON format (xem docs/10).
type HealthConfig struct {
	Enabled       bool     `toml:"enabled"`
	Sites         []string `toml:"sites"`          // host theo dõi; rỗng = mọi host trong log
	WindowMins    int      `toml:"window_mins"`    // số bucket phút giữ trong RAM
	ErrRatioPct   float64  `toml:"err_ratio_pct"`  // ngưỡng 5xx ratio cảnh báo (vd 5)
	LatencyP95Ms  int      `toml:"latency_p95_ms"` // ngưỡng p95 (ms); 0 = bỏ qua latency
	SustainedMins int      `toml:"sustained_mins"` // điều kiện phải giữ bao lâu mới báo
	CooldownMins  int      `toml:"cooldown_mins"`  // im sau khi báo
}

// Các helper chuyển ngưỡng config sang dạng package health dùng (tỷ lệ 0..1, giây).
func (c HealthConfig) ErrRatio() float64 { return c.ErrRatioPct / 100 }
func (c HealthConfig) P95Sec() float64   { return float64(c.LatencyP95Ms) / 1000 }
func (c HealthConfig) Sustained() time.Duration {
	return time.Duration(c.SustainedMins) * time.Minute
}
func (c HealthConfig) Cooldown() time.Duration {
	return time.Duration(c.CooldownMins) * time.Minute
}

// BanConfig điều khiển chặn nftables.
type BanConfig struct {
	Duration  string   `toml:"duration"`
	Whitelist []string `toml:"whitelist"`
	NftTable  string   `toml:"nft_table"`
	NftSetV4  string   `toml:"nft_set_v4"`
	NftSetV6  string   `toml:"nft_set_v6"`

	// Escalation: thời gian ban leo thang theo số lần tái phạm. Rỗng = ban phẳng
	// (luôn dùng Duration). Lần tái phạm thứ N dùng Escalation[min(N, len-1)]. Giá trị
	// "permanent" = ban gần như vĩnh viễn. Vd ["24h","168h","720h","permanent"].
	Escalation []string `toml:"escalation"`
	// EscalationMemory: giữ lịch sử offender (số lần bị ban) bao lâu sau khi ban hết
	// hạn, để đếm tái phạm. Mặc định 720h (30 ngày) khi escalation bật.
	EscalationMemory string `toml:"escalation_memory"`
}

// permanentDuration là sentinel cho ban "vĩnh viễn" (100 năm — vượt mọi vòng đời thực).
const permanentDuration = 100 * 365 * 24 * time.Hour

// EscalationDurations parse danh sách escalation thành []time.Duration ("permanent" →
// permanentDuration). Rỗng → nil (ban phẳng).
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

// EscalationMemoryDuration trả về memory window (mặc định 30 ngày khi escalation bật,
// 0 khi tắt).
func (c BanConfig) EscalationMemoryDuration() (time.Duration, error) {
	if len(c.Escalation) == 0 {
		return 0, nil
	}
	if strings.TrimSpace(c.EscalationMemory) == "" {
		return 30 * 24 * time.Hour, nil
	}
	return parseDuration(c.EscalationMemory)
}

// TelegramConfig cấu hình kênh thông báo Telegram.
type TelegramConfig struct {
	Enabled  bool   `toml:"enabled"`
	BotToken string `toml:"bot_token"`
	ChatID   string `toml:"chat_id"`
}

// EmailConfig cấu hình kênh thông báo email qua Resend (https://resend.com).
type EmailConfig struct {
	Enabled      bool     `toml:"enabled"`
	ResendAPIKey string   `toml:"resend_api_key"`
	From         string   `toml:"from"` // địa chỉ gửi (domain đã verify ở Resend)
	To           []string `toml:"to"`   // danh sách người nhận
}

// GeoIPConfig (tùy chọn) trỏ tới file MMDB OFFLINE để giải IP → vị trí/mạng. Mỗi giá
// trị là 1+ đường dẫn ngăn cách bằng dấu phẩy (bộ City của sapics tách riêng IPv4/IPv6
// nên trỏ cả hai). Rỗng = tắt. Đọc trực tiếp maxminddb nên dùng được CẢ file sapics/
// ip-location-db MIỄN PHÍ lẫn MaxMind/DB-IP chuẩn — xem internal/geoip.
type GeoIPConfig struct {
	CityDB string `toml:"city_db"` // DB vị trí (quốc gia/tỉnh/thành/toạ độ)
	ASNDB  string `toml:"asn_db"`  // DB mạng (ASN + tên ISP/tổ chức)
}

// StateConfig vị trí file state JSON.
type StateConfig struct {
	Path string `toml:"path"`
}

// Defaults là các giá trị mặc định an toàn áp dụng trước khi đọc file.
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

// Load đọc file TOML tại path, phủ lên defaults, rồi validate.
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

// BanDuration trả về thời gian ban đã parse từ Ban.Duration.
func (c Config) BanDuration() (time.Duration, error) {
	return parseDuration(c.Ban.Duration)
}

// WindowDuration trả về cửa sổ trượt dưới dạng time.Duration.
func (c Config) WindowDuration() time.Duration {
	return time.Duration(c.Detection.WindowSecs) * time.Second
}

// Whitelist trả về danh sách prefix đã parse (đã validate ở Validate).
func (c Config) Whitelist() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.Ban.Whitelist))
	for _, s := range c.Ban.Whitelist {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("whitelist entry %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// Validate kiểm tra cấu hình ở biên hệ thống; fail-fast với thông báo rõ ràng.
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

// parseDuration hỗ trợ cú pháp nft timeout: time.ParseDuration cộng hậu tố "d" (ngày).
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
