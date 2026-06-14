package config

import (
	"regexp"
	"testing"
)

func TestDefaultBadBotPatterns_AllCompile(t *testing.T) {
	for _, p := range DefaultBadBotPatterns() {
		if _, err := regexp.Compile("(?i)" + p); err != nil {
			t.Errorf("pattern %q does not compile: %v", p, err)
		}
	}
}

func TestDefaultBadBotPatterns_MatchKnownUAs(t *testing.T) {
	res := make([]*regexp.Regexp, 0, len(DefaultBadBotPatterns()))
	for _, p := range DefaultBadBotPatterns() {
		res = append(res, regexp.MustCompile("(?i)"+p))
	}
	anyMatch := func(ua string) bool {
		for _, re := range res {
			if re.MatchString(ua) {
				return true
			}
		}
		return false
	}

	bad := []string{
		"sqlmap/1.7.2#stable (https://sqlmap.org)",
		"Mozilla/5.0 (Nikto/2.5.0)",
		"Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
		"masscan/1.3",
		"WPScan v3.8.22 (https://wpscan.com/)",
		"python-requests/2.31.0",
		"Go-http-client/1.1",
		"curl/8.4.0",
		"libwww-perl/6.67",
	}
	for _, ua := range bad {
		if !anyMatch(ua) {
			t.Errorf("expected a default pattern to match bad UA %q", ua)
		}
	}

	// Real browsers and well-known good crawlers must NOT trip the defaults.
	good := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"", // empty UA is not in the defaults (legit health checks use it)
	}
	for _, ua := range good {
		if anyMatch(ua) {
			t.Errorf("good UA %q should not match any bad-bot signature", ua)
		}
	}
}

func TestValidateBadBot(t *testing.T) {
	base := Defaults() // default line_regex captures (?P<ua>...)
	base.Log.Paths = []string{"/var/log/nginx/access.log"}

	t.Run("disabled skips validation", func(t *testing.T) {
		c := base
		c.BadBot = BadBotConfig{Enabled: false, Patterns: []string{"((("}}
		if err := c.validateBadBot(); err != nil {
			t.Fatalf("disabled badbot must skip validation, got %v", err)
		}
	})

	t.Run("invalid regex fails", func(t *testing.T) {
		c := base
		c.BadBot = BadBotConfig{Enabled: true, Patterns: []string{"((("}, Threshold: 1, WindowSecs: 60}
		if err := c.validateBadBot(); err == nil {
			t.Fatal("expected error for invalid regex")
		}
	})

	t.Run("empty patterns fails", func(t *testing.T) {
		c := base
		c.BadBot = BadBotConfig{Enabled: true, Patterns: nil, Threshold: 1, WindowSecs: 60}
		if err := c.validateBadBot(); err == nil {
			t.Fatal("expected error for empty patterns")
		}
	})

	t.Run("line_regex without ua group fails", func(t *testing.T) {
		c := base
		c.Log.LineRegex = `^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?:\S+) (?P<uri>\S+)[^"]*" `
		c.BadBot = BadBotConfig{Enabled: true, Patterns: []string{`\bsqlmap\b`}, Threshold: 1, WindowSecs: 60}
		if err := c.validateBadBot(); err == nil {
			t.Fatal("expected error when line_regex lacks (?P<ua>...) group")
		}
	})

	t.Run("defaults are valid", func(t *testing.T) {
		c := base
		c.BadBot.Enabled = true
		if err := c.validateBadBot(); err != nil {
			t.Fatalf("default badbot config should validate, got %v", err)
		}
	})
}
