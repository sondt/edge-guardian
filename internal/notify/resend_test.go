package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResend_Notify(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"abc"}`))
	}))
	defer srv.Close()

	r := NewResend("re_secret", "alerts@example.com", []string{"a@x.com", "b@x.com"})
	r.endpoint = srv.URL

	ev := Event{IP: "1.2.3.4", URI: "/wp-login.php", Hits: 3, Country: "VN", ASN: "AS123 Foo",
		Location: "Hanoi, Vietnam", ExpiresAt: time.Date(2024, 1, 8, 0, 0, 0, 0, time.UTC)}
	if err := r.Notify(context.Background(), ev); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if gotAuth != "Bearer re_secret" {
		t.Fatalf("auth header=%q", gotAuth)
	}

	var payload struct {
		From    string   `json:"from"`
		To      []string `json:"to"`
		Subject string   `json:"subject"`
		HTML    string   `json:"html"`
		Text    string   `json:"text"`
	}
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if payload.From != "alerts@example.com" || len(payload.To) != 2 {
		t.Fatalf("from/to wrong: %+v", payload)
	}
	if !strings.Contains(payload.Subject, "1.2.3.4") {
		t.Fatalf("subject missing ip: %q", payload.Subject)
	}
	for _, want := range []string{"1.2.3.4", "/wp-login.php", "VN", "AS123 Foo", "Hanoi, Vietnam"} {
		if !strings.Contains(payload.HTML, want) || !strings.Contains(payload.Text, want) {
			t.Fatalf("body missing %q", want)
		}
	}
}

func TestResend_Notify_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"invalid api key"}`))
	}))
	defer srv.Close()

	r := NewResend("bad", "a@x.com", []string{"b@x.com"})
	r.endpoint = srv.URL
	err := r.Notify(context.Background(), Event{IP: "1.2.3.4"})
	if err == nil || !strings.Contains(err.Error(), "invalid api key") {
		t.Fatalf("expected API error, got %v", err)
	}
}

// counter is a Notifier that records calls and optionally fails.
type counter struct {
	calls       int
	healthCalls int
	err         error
}

func (c *counter) Notify(context.Context, Event) error {
	c.calls++
	return c.err
}
func (c *counter) NotifyHealth(context.Context, HealthEvent) error {
	c.healthCalls++
	return c.err
}

func TestMulti(t *testing.T) {
	if _, ok := Multi().(Noop); !ok {
		t.Fatal("Multi() with no channels should be Noop")
	}
	single := &counter{}
	if Multi(single) != Notifier(single) {
		t.Fatal("Multi(one) should return that one unwrapped")
	}

	a, b := &counter{}, &counter{err: errors.New("boom")}
	m := Multi(a, b)
	err := m.Notify(context.Background(), Event{IP: "1.2.3.4"})
	if a.calls != 1 || b.calls != 1 {
		t.Fatalf("both channels should be called: a=%d b=%d", a.calls, b.calls)
	}
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("multi should surface channel error, got %v", err)
	}
}
