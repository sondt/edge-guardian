package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// resendEndpoint là API gửi email của Resend (https://resend.com).
const resendEndpoint = "https://api.resend.com/emails"

// Resend gửi thông báo ban qua email bằng Resend API (REST, Bearer token).
type Resend struct {
	apiKey   string
	from     string
	to       []string
	endpoint string // cho phép override khi test
	client   *http.Client
}

// NewResend tạo notifier email qua Resend. from là địa chỉ gửi (phải thuộc domain đã
// verify ở Resend), to là danh sách người nhận.
func NewResend(apiKey, from string, to []string) *Resend {
	return &Resend{
		apiKey:   apiKey,
		from:     from,
		to:       append([]string(nil), to...),
		endpoint: resendEndpoint,
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

// Notify gửi một email cho mỗi sự kiện ban.
func (r *Resend) Notify(ctx context.Context, ev Event) error {
	return r.post(ctx, subject(ev), htmlBody(ev), textBody(ev))
}

// NotifyHealth gửi email cảnh báo sức khỏe site.
func (r *Resend) NotifyHealth(ctx context.Context, ev HealthEvent) error {
	subj := fmt.Sprintf("[edge-guardian] %s %s", healthVerb(ev), ev.Site)
	return r.post(ctx, subj, healthHTML(ev), healthText(ev))
}

// post gửi một email qua Resend (phần chung cho Notify/NotifyHealth).
func (r *Resend) post(ctx context.Context, subject, html, text string) error {
	payload := map[string]any{
		"from":    r.from,
		"to":      r.to,
		"subject": subject,
		"html":    html,
		"text":    text,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal resend payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build resend request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+r.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		// API key nằm ở header (không ở URL) nên url.Error không lộ key, nhưng vẫn
		// strip URL cho gọn log.
		return fmt.Errorf("send resend email: %w", sanitizeURLError(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("resend API status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

func healthVerb(ev HealthEvent) string {
	if ev.Firing {
		return "degraded"
	}
	return "recovered"
}

func healthText(ev HealthEvent) string {
	var b strings.Builder
	if ev.Firing {
		b.WriteString("Site degraded\n")
	} else {
		b.WriteString("Site recovered\n")
	}
	fmt.Fprintf(&b, "Site: %s\n", ev.Site)
	if ev.Summary != "" {
		fmt.Fprintf(&b, "%s\n", ev.Summary)
	}
	if ev.Detail != "" {
		fmt.Fprintf(&b, "%s\n", ev.Detail)
	}
	return b.String()
}

func healthHTML(ev HealthEvent) string {
	var b strings.Builder
	if ev.Firing {
		b.WriteString("<h3>⚠️ Site degraded</h3>")
	} else {
		b.WriteString("<h3>✅ Site recovered</h3>")
	}
	fmt.Fprintf(&b, "<p><b>%s</b></p>", escape(ev.Site))
	if ev.Summary != "" {
		fmt.Fprintf(&b, "<p>%s</p>", escape(ev.Summary))
	}
	if ev.Detail != "" {
		fmt.Fprintf(&b, "<p><code>%s</code></p>", escape(ev.Detail))
	}
	return b.String()
}

func subject(ev Event) string {
	verb := "banned"
	if ev.DryRun {
		verb = "WOULD ban (dry-run)"
	}
	return fmt.Sprintf("[edge-guardian] %s %s", verb, ev.IP)
}

func textBody(ev Event) string {
	var b strings.Builder
	if ev.DryRun {
		b.WriteString("edge-guardian (dry-run): WOULD ban\n")
	} else {
		b.WriteString("edge-guardian: IP banned\n")
	}
	fmt.Fprintf(&b, "IP: %s\n", ev.IP)
	if ev.Country != "" || ev.ASN != "" {
		fmt.Fprintf(&b, "Origin: %s %s\n", ev.Country, ev.ASN)
	}
	if ev.URI != "" {
		fmt.Fprintf(&b, "Reason: %s\n", ev.URI)
	}
	fmt.Fprintf(&b, "Hits: %d\n", ev.Hits)
	if !ev.DryRun && !ev.ExpiresAt.IsZero() {
		fmt.Fprintf(&b, "Until: %s\n", ev.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return b.String()
}

func htmlBody(ev Event) string {
	var b strings.Builder
	if ev.DryRun {
		b.WriteString("<h3>🟡 edge-guardian (dry-run): WOULD ban</h3>")
	} else {
		b.WriteString("<h3>🛑 edge-guardian: IP banned</h3>")
	}
	b.WriteString("<table cellpadding=\"4\">")
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "<tr><td><b>%s</b></td><td><code>%s</code></td></tr>", escape(k), escape(v))
		}
	}
	row("IP", ev.IP)
	row("Origin", strings.TrimSpace(ev.Country+" "+ev.ASN))
	row("Reason", ev.URI)
	row("Hits", fmt.Sprintf("%d", ev.Hits))
	if !ev.DryRun && !ev.ExpiresAt.IsZero() {
		row("Until", ev.ExpiresAt.UTC().Format(time.RFC3339))
	}
	b.WriteString("</table>")
	return b.String()
}
