package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFormatMessage(t *testing.T) {
	expires := time.Date(2024, 1, 8, 12, 0, 0, 0, time.UTC)

	t.Run("real ban", func(t *testing.T) {
		msg := formatMessage(Event{
			IP: "1.2.3.4", URI: "/wp-login.php", Hits: 3,
			ExpiresAt: expires, Country: "VN", ASN: "AS123 Foo",
		})
		for _, want := range []string{"IP banned", "1.2.3.4", "VN", "AS123 Foo", "/wp-login.php", "Hits: 3", "2024-01-08"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("message missing %q:\n%s", want, msg)
			}
		}
	})

	t.Run("dry run", func(t *testing.T) {
		msg := formatMessage(Event{IP: "5.6.7.8", DryRun: true})
		if !strings.Contains(msg, "dry-run") || !strings.Contains(msg, "WOULD ban") {
			t.Fatalf("dry-run message wrong:\n%s", msg)
		}
	})

	t.Run("includes location", func(t *testing.T) {
		msg := formatMessage(Event{IP: "1.2.3.4", Location: "Frankfurt, Hesse, Germany"})
		if !strings.Contains(msg, "Location: Frankfurt, Hesse, Germany") {
			t.Fatalf("message missing location:\n%s", msg)
		}
	})

	t.Run("omits empty location", func(t *testing.T) {
		msg := formatMessage(Event{IP: "1.2.3.4"})
		if strings.Contains(msg, "Location:") {
			t.Fatalf("message should not mention location when empty:\n%s", msg)
		}
	})

	t.Run("escapes html", func(t *testing.T) {
		msg := formatMessage(Event{IP: "1.1.1.1", URI: "/<script>&"})
		if strings.Contains(msg, "<script>") || !strings.Contains(msg, "&lt;script&gt;") {
			t.Fatalf("html not escaped:\n%s", msg)
		}
	})
}

func TestNoop(t *testing.T) {
	if err := (Noop{}).Notify(context.Background(), Event{}); err != nil {
		t.Fatalf("Noop.Notify: %v", err)
	}
}

func TestTelegram_Notify(t *testing.T) {
	// Override transport to capture the request without hitting the network.
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	tg := NewTelegram("TOKEN", []string{"-100123"})
	tg.client = srv.Client()
	tg.client.Transport = rewriteHost(srv.URL)

	if err := tg.Notify(context.Background(), Event{IP: "1.2.3.4"}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if !strings.Contains(gotPath, "/botTOKEN/sendMessage") {
		t.Fatalf("unexpected path %q", gotPath)
	}
}

func TestTelegram_Notify_MultipleRecipients(t *testing.T) {
	var mu sync.Mutex
	var gotChatIDs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ChatID string `json:"chat_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		gotChatIDs = append(gotChatIDs, body.ChatID)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	tg := NewTelegram("TOKEN", []string{"-100123", "456789", "@mychannel"})
	tg.client = srv.Client()
	tg.client.Transport = rewriteHost(srv.URL)

	if err := tg.Notify(context.Background(), Event{IP: "1.2.3.4"}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(gotChatIDs) != 3 {
		t.Fatalf("expected 3 sends (one per chat), got %d: %v", len(gotChatIDs), gotChatIDs)
	}
	for _, want := range []string{"-100123", "456789", "@mychannel"} {
		found := false
		for _, got := range gotChatIDs {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("no message sent to chat %q (got %v)", want, gotChatIDs)
		}
	}
}

func TestTelegram_Notify_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"description":"bad token"}`))
	}))
	defer srv.Close()

	tg := NewTelegram("TOKEN", []string{"-100123"})
	tg.client = srv.Client()
	tg.client.Transport = rewriteHost(srv.URL)

	err := tg.Notify(context.Background(), Event{IP: "1.2.3.4"})
	if err == nil || !strings.Contains(err.Error(), "bad token") {
		t.Fatalf("expected error containing API description, got %v", err)
	}
}

func TestTelegram_Notify_ErrorOmitsToken(t *testing.T) {
	// Point at a closed port so client.Do fails with a *url.Error carrying the URL.
	tg := NewTelegram("SECRETTOKEN", []string{"-100123"})
	tg.client = &http.Client{Timeout: time.Second}
	tg.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Post", URL: r.URL.String(), Err: errTest}
	})

	err := tg.Notify(context.Background(), Event{IP: "1.2.3.4"})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Fatalf("error leaks bot token: %v", err)
	}
}

var errTest = &dialErr{}

type dialErr struct{}

func (*dialErr) Error() string { return "connection refused" }

// rewriteHost redirects api.telegram.org requests to the test server.
func rewriteHost(target string) http.RoundTripper {
	u := strings.TrimPrefix(target, "http://")
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		r.URL.Host = u
		return http.DefaultTransport.RoundTrip(r)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
