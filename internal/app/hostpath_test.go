package app

import (
	"github.com/sondt/edge-guardian/internal/parse"
	"testing"
)

func TestHostPath(t *testing.T) {
	cases := []struct {
		ev   parse.Event
		want string
	}{
		{parse.Event{Host: "example.com", URI: "/cgi-bin/magicBox.cgi?action=getLanguageCaps"}, "example.com/cgi-bin/magicBox.cgi?action=getLanguageCaps"},
		{parse.Event{URI: "/wp-login.php"}, "/wp-login.php"},
		{parse.Event{Host: "a.vn", URI: "/.env"}, "a.vn/.env"},
	}
	for _, c := range cases {
		if got := hostPath(c.ev); got != c.want {
			t.Errorf("hostPath=%q want %q", got, c.want)
		}
	}
}
