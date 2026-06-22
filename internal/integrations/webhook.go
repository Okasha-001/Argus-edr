package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Webhook posts the notification as JSON to a generic endpoint — the
// lowest-common-denominator integration that any self-hosted receiver can accept.
type Webhook struct {
	url    string
	client *http.Client
}

// NewWebhook returns a webhook notifier for url, or nil when url is empty so the
// caller can add it to a Multi unconditionally.
func NewWebhook(url string) *Webhook {
	if url == "" {
		return nil
	}
	return &Webhook{url: url, client: &http.Client{Timeout: 10 * time.Second}}
}

type webhookPayload struct {
	Title     string `json:"title"`
	Summary   string `json:"summary,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Host      string `json:"host,omitempty"`
	RuleID    string `json:"rule_id,omitempty"`
	Technique string `json:"technique,omitempty"`
}

func (w *Webhook) Notify(ctx context.Context, n Notification) error {
	body, err := json.Marshal(webhookPayload(n))
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}
	return postJSON(ctx, w.client, w.url, body)
}

func (w *Webhook) Name() string { return "webhook" }

// postJSON is shared by the webhook and Slack notifiers: it sends body to url and
// treats any non-2xx response as a delivery failure.
func postJSON(ctx context.Context, client *http.Client, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("deliver: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("endpoint returned %s", resp.Status)
	}
	return nil
}
