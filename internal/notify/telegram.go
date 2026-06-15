package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Telegram sends notifications via the Bot API using the net/http stdlib. Each message
// is delivered to every configured chat ID (groups, users, channels).
type Telegram struct {
	token   string
	chatIDs []string
	client  *http.Client
}

// NewTelegram creates a Telegram notifier sending to one or more chat IDs.
func NewTelegram(token string, chatIDs []string) *Telegram {
	return &Telegram{
		token:   token,
		chatIDs: append([]string(nil), chatIDs...),
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Notify formats and sends a ban message.
func (t *Telegram) Notify(ctx context.Context, ev Event) error {
	return t.send(ctx, formatMessage(ev))
}

// NotifyHealth sends a site health alert (degraded/down/recovered).
func (t *Telegram) NotifyHealth(ctx context.Context, ev HealthEvent) error {
	return t.send(ctx, formatHealthMessage(ev))
}

// send delivers text to every configured chat ID. It is best-effort: a failure to one
// chat does not stop the others; all errors are joined and returned.
func (t *Telegram) send(ctx context.Context, text string) error {
	var errs []error
	for _, chatID := range t.chatIDs {
		if err := t.sendTo(ctx, chatID, text); err != nil {
			errs = append(errs, fmt.Errorf("chat %s: %w", chatID, err))
		}
	}
	return errors.Join(errs...)
}

// sendTo POSTs one message to a single chat ID.
func (t *Telegram) sendTo(ctx context.Context, chatID, text string) error {
	body := map[string]string{"chat_id": chatID, "text": text, "parse_mode": "HTML"}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal telegram payload: %w", err)
	}
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("send telegram message: %w", sanitizeURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("telegram API status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

func formatHealthMessage(ev HealthEvent) string {
	var b strings.Builder
	if ev.Firing {
		b.WriteString("⚠️ <b>Site degraded</b>\n")
	} else {
		b.WriteString("✅ <b>Site recovered</b>\n")
	}
	fmt.Fprintf(&b, "<b>%s</b>\n", escape(ev.Site))
	if ev.Summary != "" {
		fmt.Fprintf(&b, "%s\n", escape(ev.Summary))
	}
	if ev.Detail != "" {
		b.WriteString(escape(ev.Detail))
	}
	return b.String()
}

func formatMessage(ev Event) string {
	var b strings.Builder
	if ev.DryRun {
		b.WriteString("🟡 <b>edge-guardian (dry-run): WOULD ban</b>\n")
	} else {
		b.WriteString("🛑 <b>edge-guardian: IP banned</b>\n")
	}
	fmt.Fprintf(&b, "IP: <code>%s</code>\n", escape(ev.IP))
	if ev.Country != "" || ev.ASN != "" {
		fmt.Fprintf(&b, "Geo: %s %s\n", escape(ev.Country), escape(ev.ASN))
	}
	if ev.Location != "" {
		fmt.Fprintf(&b, "Location: %s\n", escape(ev.Location))
	}
	if ev.URI != "" {
		fmt.Fprintf(&b, "Sample: <code>%s</code>\n", escape(ev.URI))
	}
	fmt.Fprintf(&b, "Hits: %d\n", ev.Hits)
	if !ev.DryRun && !ev.ExpiresAt.IsZero() {
		fmt.Fprintf(&b, "Until: %s", ev.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return b.String()
}

// sanitizeURLError peels every *url.Error layer off err. Each layer's Error() string
// embeds the request URL, which contains the bot token; net/http can wrap the
// transport error more than once. The innermost non-url error (e.g. the dial error)
// does not carry the URL, so returning it keeps the token out of logs.
func sanitizeURLError(err error) error {
	for {
		var ue *url.Error
		if !errors.As(err, &ue) {
			return err
		}
		if ue.Err == nil {
			return fmt.Errorf("%s failed", ue.Op)
		}
		err = ue.Err
	}
}

// escape escapes the special characters of Telegram's HTML parse_mode.
func escape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}
