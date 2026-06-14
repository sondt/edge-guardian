package detect

import (
	"testing"
	"time"
)

func TestMatcher_IsBad(t *testing.T) {
	m, err := NewMatcher([]string{
		`\.(php|env|git|sql|bak)(\?|/|$)`,
		`/(wp-admin|wp-login|xmlrpc)`,
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		uri  string
		want bool
	}{
		{"/wp-login.php", true},
		{"/index.PHP", true}, // case-insensitive
		{"/.env", true},
		{"/app/.git/config", true},
		{"/wp-admin/", true},
		{"/", false},
		{"/api/users", false},
		{"/assets/main.js", false},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			if got := m.IsBad(tt.uri); got != tt.want {
				t.Fatalf("IsBad(%q)=%v want %v", tt.uri, got, tt.want)
			}
		})
	}
}

func TestNewMatcher_Errors(t *testing.T) {
	if _, err := NewMatcher(nil); err == nil {
		t.Fatal("expected error for empty patterns")
	}
	if _, err := NewMatcher([]string{`(`}); err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestWindow_Threshold(t *testing.T) {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("threshold 1 trips immediately", func(t *testing.T) {
		w := NewWindow(1, 60*time.Second)
		count, tripped := w.Record("1.1.1.1", base)
		if count != 1 || !tripped {
			t.Fatalf("count=%d tripped=%v want 1,true", count, tripped)
		}
	})

	t.Run("threshold 3 trips on third within window", func(t *testing.T) {
		w := NewWindow(3, 60*time.Second)
		if _, tripped := w.Record("2.2.2.2", base); tripped {
			t.Fatal("should not trip on 1st")
		}
		if _, tripped := w.Record("2.2.2.2", base.Add(10*time.Second)); tripped {
			t.Fatal("should not trip on 2nd")
		}
		count, tripped := w.Record("2.2.2.2", base.Add(20*time.Second))
		if count != 3 || !tripped {
			t.Fatalf("count=%d tripped=%v want 3,true", count, tripped)
		}
	})

	t.Run("old hits slide out of window", func(t *testing.T) {
		w := NewWindow(3, 60*time.Second)
		w.Record("3.3.3.3", base)
		w.Record("3.3.3.3", base.Add(10*time.Second))
		// 70s later: first two are outside the 60s window.
		count, tripped := w.Record("3.3.3.3", base.Add(80*time.Second))
		if count != 1 || tripped {
			t.Fatalf("count=%d tripped=%v want 1,false", count, tripped)
		}
	})

	t.Run("distinct keys tracked separately", func(t *testing.T) {
		w := NewWindow(2, 60*time.Second)
		w.Record("a", base)
		if _, tripped := w.Record("b", base); tripped {
			t.Fatal("key b should not trip from key a's hit")
		}
	})
}

func TestWindow_ForgetAndPrune(t *testing.T) {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	w := NewWindow(5, 60*time.Second)

	w.Record("x", base)
	w.Record("x", base.Add(time.Second))
	w.Forget("x")
	if count, _ := w.Record("x", base.Add(2*time.Second)); count != 1 {
		t.Fatalf("after Forget, count=%d want 1", count)
	}

	w.Record("y", base)
	w.Prune(base.Add(2 * time.Minute)) // y's hit is now stale
	if count, _ := w.Record("y", base.Add(2*time.Minute)); count != 1 {
		t.Fatalf("after Prune, count=%d want 1", count)
	}
}

func TestNewWindow_ClampsThreshold(t *testing.T) {
	w := NewWindow(0, time.Minute)
	if _, tripped := w.Record("k", time.Now()); !tripped {
		t.Fatal("threshold 0 should be clamped to 1 and trip immediately")
	}
}
