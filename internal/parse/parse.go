// Package parse extracts IP, URI (and optionally UA + health fields) from a log line.
// It supports two formats: nginx combined (regex) and nginx JSON (escape=json) — auto-detecting
// the format per line (starting with '{' → JSON). The same Event serves both detection and health.
package parse

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Event is the result of parsing a log line. IP/URI are always present for a valid line; the other
// fields are filled only when the log carries enough information (UA for bad-bot; Host/Status/RequestTime/Bytes/
// UpstreamStatus for health).
type Event struct {
	IP  string
	URI string
	UA  string // user-agent — combined needs group (?P<ua>...); JSON reads field "ua"

	// Health fields (0/"" if the log lacks them).
	Host           string
	Status         int
	RequestTime    float64 // seconds
	Bytes          uint64
	UpstreamStatus string
}

// LineParser applies a regex with named groups `ip` and `uri` (required) to a combined line.
// The optional groups `ua`, `status`, `bytes` are extracted if present. JSON lines are detected
// and parsed separately, not via regex.
type LineParser struct {
	re        *regexp.Regexp
	ipIdx     int
	uriIdx    int
	uaIdx     int // -1 if the regex has no ua group
	statusIdx int // -1 if no status group
	bytesIdx  int // -1 if no bytes group
}

// NewLineParser compiles the pattern and determines the group positions.
func NewLineParser(pattern string) (*LineParser, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("compile line_regex: %w", err)
	}
	p := &LineParser{re: re, ipIdx: -1, uriIdx: -1, uaIdx: -1, statusIdx: -1, bytesIdx: -1}
	for i, name := range re.SubexpNames() {
		switch name {
		case "ip":
			p.ipIdx = i
		case "uri":
			p.uriIdx = i
		case "ua":
			p.uaIdx = i
		case "status":
			p.statusIdx = i
		case "bytes":
			p.bytesIdx = i
		}
	}
	if p.ipIdx == -1 || p.uriIdx == -1 {
		return nil, fmt.Errorf("line_regex must contain named groups (?P<ip>...) and (?P<uri>...)")
	}
	return p, nil
}

// HasUA reports whether the regex has a `ua` group (so the bad-bot detector can fail-fast if missing).
// JSON lines can always carry `ua`, so they don't depend on this flag.
func (p *LineParser) HasUA() bool { return p.uaIdx != -1 }

// Parse returns an Event and ok=true if the line is valid. JSON lines (starting with '{') are parsed as JSON;
// the rest via regex.
func (p *LineParser) Parse(line string) (Event, bool) {
	if s := strings.TrimSpace(line); len(s) > 0 && s[0] == '{' {
		return parseJSON(s)
	}
	return p.parseRegex(line)
}

func (p *LineParser) parseRegex(line string) (Event, bool) {
	m := p.re.FindStringSubmatch(line)
	if m == nil {
		return Event{}, false
	}
	ip := m[p.ipIdx]
	uri := m[p.uriIdx]
	if ip == "" || uri == "" {
		return Event{}, false
	}
	ev := Event{IP: ip, URI: uri}
	if p.uaIdx != -1 {
		ev.UA = m[p.uaIdx]
	}
	if p.statusIdx != -1 {
		ev.Status, _ = strconv.Atoi(m[p.statusIdx])
	}
	if p.bytesIdx != -1 {
		ev.Bytes, _ = strconv.ParseUint(m[p.bytesIdx], 10, 64)
	}
	return ev, true
}

// jsonAccess maps the recommended nginx escape=json format (see docs/10).
type jsonAccess struct {
	Host           string  `json:"host"`
	RemoteAddr     string  `json:"remote_addr"`
	URI            string  `json:"uri"`
	UA             string  `json:"ua"`
	Status         int     `json:"status"`
	RequestTime    float64 `json:"request_time"`
	Bytes          uint64  `json:"bytes"`
	UpstreamStatus string  `json:"upstream_status"`
}

// parseJSON reads a JSON access log line into an Event. A broken line / missing remote_addr → ok=false.
func parseJSON(s string) (Event, bool) {
	var j jsonAccess
	if err := json.Unmarshal([]byte(s), &j); err != nil {
		return Event{}, false
	}
	if j.RemoteAddr == "" {
		return Event{}, false
	}
	return Event{
		IP:             j.RemoteAddr,
		URI:            j.URI,
		UA:             j.UA,
		Host:           j.Host,
		Status:         j.Status,
		RequestTime:    j.RequestTime,
		Bytes:          j.Bytes,
		UpstreamStatus: j.UpstreamStatus,
	}, true
}
