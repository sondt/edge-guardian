package parse

import "testing"

const nginxRegex = `^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?:\S+) (?P<uri>\S+)[^"]*" `

// nginxRegexUA also captures the trailing user-agent field (combined log format).
const nginxRegexUA = `^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?:\S+) (?P<uri>\S+)[^"]*" \d+ \S+ "[^"]*" "(?P<ua>[^"]*)"`

// nginxRegexFull captures status/bytes/ua (combined, for health from combined logs).
const nginxRegexFull = `^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?:\S+) (?P<uri>\S+)[^"]*" (?P<status>\d+) (?P<bytes>\S+) "[^"]*" "(?P<ua>[^"]*)"`

func TestNewLineParser_RequiresNamedGroups(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"valid", nginxRegex, false},
		{"missing uri", `^(?P<ip>\S+) `, true},
		{"missing ip", `"(?P<uri>\S+)"`, true},
		{"bad regex", `(?P<ip>\S+`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewLineParser(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestLineParser_Parse(t *testing.T) {
	p, err := NewLineParser(nginxRegex)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		line    string
		wantIP  string
		wantURI string
		wantOK  bool
	}{
		{
			name:    "combined log",
			line:    `1.2.3.4 - - [10/Oct/2024:13:55:36 +0000] "GET /wp-login.php HTTP/1.1" 404 152 "-" "curl"`,
			wantIP:  "1.2.3.4",
			wantURI: "/wp-login.php",
			wantOK:  true,
		},
		{
			name:    "ipv6",
			line:    `2001:db8::1 - - [10/Oct/2024:13:55:36 +0000] "POST /.env HTTP/1.1" 404 0 "-" "-"`,
			wantIP:  "2001:db8::1",
			wantURI: "/.env",
			wantOK:  true,
		},
		{
			name:   "non-matching line",
			line:   "garbage line without structure",
			wantOK: false,
		},
		{
			name:   "empty",
			line:   "",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, ok := p.Parse(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v want=%v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if ev.IP != tt.wantIP || ev.URI != tt.wantURI {
				t.Fatalf("got (%q,%q) want (%q,%q)", ev.IP, ev.URI, tt.wantIP, tt.wantURI)
			}
		})
	}
}

func TestLineParser_UserAgent(t *testing.T) {
	plain, _ := NewLineParser(nginxRegex)
	if plain.HasUA() {
		t.Fatal("plain regex must report HasUA()=false")
	}
	// Without a ua group, UA is empty even on a combined-format line.
	ev, ok := plain.Parse(`1.2.3.4 - - [10/Oct/2024:13:55:36 +0000] "GET /a HTTP/1.1" 200 12 "-" "sqlmap/1.7"`)
	if !ok || ev.UA != "" {
		t.Fatalf("plain parser UA=%q want empty", ev.UA)
	}

	ua, err := NewLineParser(nginxRegexUA)
	if err != nil {
		t.Fatal(err)
	}
	if !ua.HasUA() {
		t.Fatal("ua regex must report HasUA()=true")
	}
	tests := []struct {
		line   string
		wantUA string
	}{
		{`1.2.3.4 - - [10/Oct/2024:13:55:36 +0000] "GET /a HTTP/1.1" 200 12 "-" "sqlmap/1.7.2#stable"`, "sqlmap/1.7.2#stable"},
		{`9.9.9.9 - - [10/Oct/2024:13:55:36 +0000] "GET /b HTTP/1.1" 404 0 "https://ref" "Mozilla/5.0 (X11)"`, "Mozilla/5.0 (X11)"},
		{`8.8.8.8 - - [10/Oct/2024:13:55:36 +0000] "GET /c HTTP/1.1" 200 5 "-" "-"`, "-"},
	}
	for _, tt := range tests {
		ev, ok := ua.Parse(tt.line)
		if !ok {
			t.Fatalf("line did not parse: %q", tt.line)
		}
		if ev.UA != tt.wantUA {
			t.Fatalf("UA=%q want %q", ev.UA, tt.wantUA)
		}
	}
}

func TestLineParser_StatusBytes(t *testing.T) {
	p, err := NewLineParser(nginxRegexFull)
	if err != nil {
		t.Fatal(err)
	}
	ev, ok := p.Parse(`1.2.3.4 - - [10/Oct/2024:13:55:36 +0000] "GET /a HTTP/1.1" 503 4096 "-" "curl"`)
	if !ok {
		t.Fatal("did not parse")
	}
	if ev.Status != 503 {
		t.Fatalf("status=%d want 503", ev.Status)
	}
	if ev.Bytes != 4096 {
		t.Fatalf("bytes=%d want 4096", ev.Bytes)
	}
}

func TestLineParser_JSON(t *testing.T) {
	p, _ := NewLineParser(nginxRegex) // regex is just the combined fallback
	line := `{"time":"2024-10-10T13:55:36+00:00","host":"example.com","remote_addr":"203.0.113.9",` +
		`"method":"GET","uri":"/wp-login.php","status":404,"request_time":0.231,` +
		`"upstream_status":"404","upstream_time":"0.230","bytes":512,"ua":"sqlmap/1.7"}`
	ev, ok := p.Parse(line)
	if !ok {
		t.Fatal("json line should parse")
	}
	if ev.IP != "203.0.113.9" || ev.URI != "/wp-login.php" || ev.UA != "sqlmap/1.7" {
		t.Fatalf("detection fields wrong: %+v", ev)
	}
	if ev.Host != "example.com" || ev.Status != 404 || ev.Bytes != 512 {
		t.Fatalf("health fields wrong: %+v", ev)
	}
	if ev.RequestTime < 0.23 || ev.RequestTime > 0.24 {
		t.Fatalf("request_time=%v want ~0.231", ev.RequestTime)
	}
	if ev.UpstreamStatus != "404" {
		t.Fatalf("upstream_status=%q", ev.UpstreamStatus)
	}
}

func TestLineParser_JSONInvalid(t *testing.T) {
	p, _ := NewLineParser(nginxRegex)
	for _, line := range []string{`{not json}`, `{"status":200}`, `{ "remote_addr": "" }`} {
		if _, ok := p.Parse(line); ok {
			t.Fatalf("line should NOT parse: %q", line)
		}
	}
}
