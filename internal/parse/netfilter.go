package parse

import (
	"regexp"
	"strings"
)

// A kernel netfilter LOG line (as recorded by journald/rsyslog) looks like:
//
//	... kernel: EDGEGUARD-SCAN IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=10.0.0.1 ... PROTO=TCP SPT=44321 DPT=2222 ...
//
// We only need the prefix (to distinguish scan/honeypot), SRC (source IP) and DPT (destination port).
var (
	nfSrcRe = regexp.MustCompile(`\bSRC=(\S+)`)
	nfDptRe = regexp.MustCompile(`\bDPT=(\d+)`)
)

// NetfilterEvent is the result of parsing a LOG line with a given prefix.
type NetfilterEvent struct {
	IP   string // SRC=
	Port string // DPT=
}

// NetfilterParser matches lines carrying a specific prefix (e.g. "EDGEGUARD-SCAN").
type NetfilterParser struct {
	prefix string
}

// NewNetfilterParser creates a parser for a LOG prefix. Empty prefix = match any line with
// SRC=/DPT= (not recommended; set a prefix to separate sources).
func NewNetfilterParser(prefix string) *NetfilterParser {
	return &NetfilterParser{prefix: prefix}
}

// Parse returns (event, true) if the line contains the prefix and has a valid SRC + DPT.
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
