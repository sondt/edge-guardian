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

// Telegram gửi thông báo qua Bot API bằng net/http stdlib.
type Telegram struct {
	token  string
	chatID string
	client *http.Client
}

// NewTelegram tạo notifier Telegram. apiBase rỗng => dùng endpoint mặc định.
func NewTelegram(token, chatID string) *Telegram {
	return &Telegram{
		token:  token,
		chatID: chatID,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Notify định dạng và gửi một message ban.
func (t *Telegram) Notify(ctx context.Context, ev Event) error {
	return t.send(ctx, formatMessage(ev))
}

// NotifyHealth gửi cảnh báo sức khỏe site (degraded/down/recovered).
func (t *Telegram) NotifyHealth(ctx context.Context, ev HealthEvent) error {
	return t.send(ctx, formatHealthMessage(ev))
}

// send là phần POST chung cho Notify/NotifyHealth.
func (t *Telegram) send(ctx context.Context, text string) error {
	body := map[string]string{"chat_id": t.chatID, "text": text, "parse_mode": "HTML"}
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

// escape thoát các ký tự đặc biệt của HTML parse_mode của Telegram.
func escape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}
