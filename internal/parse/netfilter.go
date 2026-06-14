package parse

import (
	"regexp"
	"strings"
)

// Dòng kernel netfilter LOG (như journald/rsyslog ghi lại) có dạng:
//
//	... kernel: EDGEGUARD-SCAN IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=10.0.0.1 ... PROTO=TCP SPT=44321 DPT=2222 ...
//
// Ta chỉ cần prefix (để phân biệt scan/honeypot), SRC (IP nguồn) và DPT (port đích).
var (
	nfSrcRe = regexp.MustCompile(`\bSRC=(\S+)`)
	nfDptRe = regexp.MustCompile(`\bDPT=(\d+)`)
)

// NetfilterEvent là kết quả parse một dòng LOG có prefix cho trước.
type NetfilterEvent struct {
	IP   string // SRC=
	Port string // DPT=
}

// NetfilterParser khớp các dòng có một prefix cụ thể (vd "EDGEGUARD-SCAN").
type NetfilterParser struct {
	prefix string
}

// NewNetfilterParser tạo parser cho một prefix LOG. prefix rỗng = khớp mọi dòng có
// SRC=/DPT= (không khuyến nghị; nên đặt prefix để tách nguồn).
func NewNetfilterParser(prefix string) *NetfilterParser {
	return &NetfilterParser{prefix: prefix}
}

// Parse trả về (event, true) nếu dòng chứa prefix và có SRC + DPT hợp lệ.
func (p *NetfilterParser) Parse(line string) (NetfilterEvent, bool) {
	if p.prefix != "" && !strings.Contains(line, p.prefix) {
		return NetfilterEvent{}, false
	}
	src := nfSrcRe.FindStringSubmatch(line)
	if src == nil {
		return NetfilterEvent{}, false
	}
	dpt := nfDptRe.FindStringSubmatch(line)
	if dpt == nil {
		return NetfilterEvent{}, false
	}
	return NetfilterEvent{IP: src[1], Port: dpt[1]}, true
}
