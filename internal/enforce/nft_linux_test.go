//go:build linux

package enforce

import "testing"

func TestBaselineAcceptDetection(t *testing.T) {
	tests := []struct {
		name       string
		dump       string
		wantLo     bool
		wantEstabl bool
	}{
		{
			name: "healed chain has both",
			dump: `table inet edge_guardian {
	chain input {
		type filter hook input priority -10; policy accept;
		iif "lo" accept
		ct state established,related accept
		ip saddr @blocklist4 drop
		ip saddr @blockset4 drop
	}
}`,
			wantLo: true, wantEstabl: true,
		},
		{
			name: "broken chain: drops only",
			dump: `table inet edge_guardian {
	chain input {
		type filter hook input priority -10; policy accept;
		ip saddr @blocklist4 drop
		ip saddr @blockset4 drop
	}
}`,
			wantLo: false, wantEstabl: false,
		},
		{
			name:       "iifname variant still detected",
			dump:       `		iifname "lo" accept`,
			wantLo:     true,
			wantEstabl: false,
		},
		{
			name:       "established only",
			dump:       `		ct state established,related accept`,
			wantLo:     false,
			wantEstabl: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := loAcceptRe.MatchString(tt.dump); got != tt.wantLo {
				t.Errorf("loAcceptRe = %v, want %v", got, tt.wantLo)
			}
			if got := estAcceptRe.MatchString(tt.dump); got != tt.wantEstabl {
				t.Errorf("estAcceptRe = %v, want %v", got, tt.wantEstabl)
			}
		})
	}
}
