// Package detect holds the detection logic: URI pattern matcher and sliding-window.
package detect

import (
	"fmt"
	"regexp"
)

// Matcher checks whether a URI matches any "bad" pattern.
// The patterns are compiled case-insensitive.
type Matcher struct {
	patterns []*regexp.Regexp
}

// NewMatcher compiles the pattern list (auto-adding the (?i) flag).
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

// IsBad returns true if uri matches at least one pattern.
func (m *Matcher) IsBad(uri string) bool {
	for _, re := range m.patterns {
		if re.MatchString(uri) {
			return true
		}
	}
	return false
}
