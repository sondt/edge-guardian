package config

import (
	"testing"
	"time"
)

func TestValidateHealth(t *testing.T) {
	base := Defaults()
	base.Log.Paths = []string{"/var/log/nginx/access.log"}

	t.Run("disabled skips validation", func(t *testing.T) {
		c := base
		c.Health = HealthConfig{Enabled: false, WindowMins: 0}
		if err := c.validateHealth(); err != nil {
			t.Fatalf("disabled health must skip validation, got %v", err)
		}
	})

	t.Run("defaults are valid", func(t *testing.T) {
		c := base
		c.Health.Enabled = true
		if err := c.validateHealth(); err != nil {
			t.Fatalf("default health config should validate, got %v", err)
		}
	})

	bad := []struct {
		name string
		mut  func(*HealthConfig)
	}{
		{"window<1", func(h *HealthConfig) { h.WindowMins = 0 }},
		{"err pct >100", func(h *HealthConfig) { h.ErrRatioPct = 150 }},
		{"err pct <0", func(h *HealthConfig) { h.ErrRatioPct = -1 }},
		{"latency<0", func(h *HealthConfig) { h.LatencyP95Ms = -1 }},
		{"sustained<1", func(h *HealthConfig) { h.SustainedMins = 0 }},
		{"cooldown<0", func(h *HealthConfig) { h.CooldownMins = -1 }},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			c := base
			c.Health = HealthConfig{
				Enabled: true, WindowMins: 180, ErrRatioPct: 5,
				LatencyP95Ms: 2000, SustainedMins: 5, CooldownMins: 30,
			}
			tt.mut(&c.Health)
			if err := c.validateHealth(); err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
		})
	}
}

func TestHealthConfig_Helpers(t *testing.T) {
	c := HealthConfig{ErrRatioPct: 5, LatencyP95Ms: 2000, SustainedMins: 5, CooldownMins: 30}
	if c.ErrRatio() != 0.05 {
		t.Fatalf("ErrRatio=%v want 0.05", c.ErrRatio())
	}
	if c.P95Sec() != 2.0 {
		t.Fatalf("P95Sec=%v want 2.0", c.P95Sec())
	}
	if c.Sustained() != 5*time.Minute {
		t.Fatalf("Sustained=%v", c.Sustained())
	}
	if c.Cooldown() != 30*time.Minute {
		t.Fatalf("Cooldown=%v", c.Cooldown())
	}
}
