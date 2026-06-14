package parse

import (
	"strings"
	"testing"
)

func TestSSHParser_Parse(t *testing.T) {
	p := NewSSHParser()
	tests := []struct {
		name       string
		line       string
		wantIP     string
		wantOK     bool
		reasonHas  string
		invalidHas bool
	}{
		{
			name:      "failed password valid user",
			line:      "May 12 10:00:01 host sshd[123]: Failed password for root from 218.92.0.5 port 54321 ssh2",
			wantIP:    "218.92.0.5",
			wantOK:    true,
			reasonHas: "user root",
		},
		{
			name:       "failed password invalid user",
			line:       "May 12 10:00:02 host sshd[124]: Failed password for invalid user admin from 45.6.7.8 port 5678 ssh2",
			wantIP:     "45.6.7.8",
			wantOK:     true,
			reasonHas:  "invalid user admin",
			invalidHas: true,
		},
		{
			name:   "ipv6 source",
			line:   "Failed password for root from 2001:db8::dead port 22 ssh2",
			wantIP: "2001:db8::dead",
			wantOK: true,
		},
		{
			name:   "accepted login is not a failure",
			line:   "Accepted password for root from 10.0.0.1 port 5 ssh2",
			wantOK: false,
		},
		{
			name:   "unrelated line",
			line:   "May 12 10:00:03 host CRON[999]: pam_unix(cron:session): session opened",
			wantOK: false,
		},
		{
			name:   "empty",
			line:   "",
			wantOK: false,
		},
		{
			// Log-injection attempt: a crafted username embeds a fake "from <victim>
			// port 22". sshd appends the REAL peer last, so we must extract that, not
			// the spoofed one.
			name:   "username injection does not spoof source ip",
			line:   "host sshd[1]: Failed password for invalid user x from 8.8.8.8 port 22 ssh2 from 45.13.22.7 port 5678 ssh2",
			wantIP: "45.13.22.7",
			wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, reason, ok := p.Parse(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v want=%v (reason=%q)", ok, tt.wantOK, reason)
			}
			if !ok {
				return
			}
			if ip != tt.wantIP {
				t.Fatalf("ip=%q want=%q", ip, tt.wantIP)
			}
			if tt.reasonHas != "" && !strings.Contains(reason, tt.reasonHas) {
				t.Fatalf("reason=%q missing %q", reason, tt.reasonHas)
			}
			if tt.invalidHas && !strings.Contains(reason, "invalid user") {
				t.Fatalf("reason=%q should flag invalid user", reason)
			}
		})
	}
}
