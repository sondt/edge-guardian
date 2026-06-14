package config

import "testing"

func TestValidateRateLimit(t *testing.T) {
	base := Defaults()
	base.Log.Paths = []string{"/var/log/nginx/access.log"}

	t.Run("disabled skips validation", func(t *testing.T) {
		c := base
		c.RateLimit = RateLimitConfig{Enabled: false, Threshold: 0, WindowSecs: 0}
		if err := c.validateRateLimit(); err != nil {
			t.Fatalf("disabled ratelimit must skip validation, got %v", err)
		}
	})

	t.Run("bad threshold fails", func(t *testing.T) {
		c := base
		c.RateLimit = RateLimitConfig{Enabled: true, Threshold: 0, WindowSecs: 10}
		if err := c.validateRateLimit(); err == nil {
			t.Fatal("expected error for threshold < 1")
		}
	})

	t.Run("bad window fails", func(t *testing.T) {
		c := base
		c.RateLimit = RateLimitConfig{Enabled: true, Threshold: 300, WindowSecs: 0}
		if err := c.validateRateLimit(); err == nil {
			t.Fatal("expected error for window_secs < 1")
		}
	})

	t.Run("defaults are valid", func(t *testing.T) {
		c := base
		c.RateLimit.Enabled = true
		if err := c.validateRateLimit(); err != nil {
			t.Fatalf("default ratelimit config should validate, got %v", err)
		}
	})

	t.Run("window duration", func(t *testing.T) {
		c := RateLimitConfig{WindowSecs: 10}
		if c.WindowDuration().Seconds() != 10 {
			t.Fatalf("WindowDuration=%v want 10s", c.WindowDuration())
		}
	})
}
