// Package detect chứa logic phát hiện: matcher pattern URI và sliding-window.
package detect

import (
	"fmt"
	"regexp"
)

// Matcher kiểm tra một URI có khớp bất kỳ pattern "xấu" nào không.
// Các pattern được biên dịch case-insensitive.
type Matcher struct {
	patterns []*regexp.Regexp
}

// NewMatcher biên dịch danh sách pattern (tự thêm cờ (?i)).
func NewMatcher(patterns []string) (*Matcher, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("matcher needs at least one pattern")
	}
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("compile pattern %q: %w", p, err)
		}
		compiled = append(compiled, re)
	}
	return &Matcher{patterns: compiled}, nil
}

// IsBad trả về true nếu uri khớp ít nhất một pattern.
func (m *Matcher) IsBad(uri string) bool {
	for _, re := range m.patterns {
		if re.MatchString(uri) {
			return true
		}
	}
	return false
}
