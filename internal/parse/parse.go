// Package parse trích xuất IP, URI (và tùy chọn UA + trường health) từ một dòng log.
// Hỗ trợ hai định dạng: nginx combined (regex) và nginx JSON (escape=json) — tự nhận
// dạng theo dòng (bắt đầu bằng '{' → JSON). Cùng một Event phục vụ cả detection lẫn health.
package parse

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Event là kết quả parse một dòng log. IP/URI luôn có cho dòng hợp lệ; các trường còn
// lại chỉ điền khi log mang đủ thông tin (UA cho bad-bot; Host/Status/RequestTime/Bytes/
// UpstreamStatus cho health).
type Event struct {
	IP  string
	URI string
	UA  string // user-agent — combined cần group (?P<ua>...); JSON đọc field "ua"

	// Trường health (0/"" nếu log không có).
	Host           string
	Status         int
	RequestTime    float64 // giây
	Bytes          uint64
	UpstreamStatus string
}

// LineParser áp một regex có named group `ip` và `uri` (bắt buộc) lên dòng combined.
// Các group tùy chọn `ua`, `status`, `bytes` được trích nếu có. Dòng JSON được nhận dạng
// và parse riêng, không qua regex.
type LineParser struct {
	re        *regexp.Regexp
	ipIdx     int
	uriIdx    int
	uaIdx     int // -1 nếu regex không có group ua
	statusIdx int // -1 nếu không có group status
	bytesIdx  int // -1 nếu không có group bytes
}

// NewLineParser biên dịch pattern và xác định vị trí các group.
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

// HasUA cho biết regex có group `ua` hay không (để bad-bot detector fail-fast nếu thiếu).
// Dòng JSON luôn có thể mang `ua` nên không phụ thuộc cờ này.
func (p *LineParser) HasUA() bool { return p.uaIdx != -1 }

// Parse trả về Event và ok=true nếu dòng hợp lệ. Dòng JSON (bắt đầu '{') parse theo JSON;
// còn lại theo regex.
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

// jsonAccess ánh xạ định dạng nginx escape=json khuyến nghị (xem docs/10).
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

// parseJSON đọc một dòng JSON access log thành Event. Dòng hỏng/thiếu remote_addr → ok=false.
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
