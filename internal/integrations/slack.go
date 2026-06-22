package integrations

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Slack posts to a Slack or Mattermost incoming webhook — both accept the same
// {"text": ...} payload, so one notifier covers both FOSS-friendly chat systems.
type Slack struct {
	url    string
	client *http.Client
}

// NewSlack returns a Slack/Mattermost notifier for an incoming-webhook url, or
// nil when url is empty.
func NewSlack(url string) *Slack {
	if url == "" {
		return nil
	}
	return &Slack{url: url, client: &http.Client{Timeout: 10 * time.Second}}
}

func (s *Slack) Notify(ctx context.Context, n Notification) error {
	text := n.textLine()
	if n.Summary != "" {
		text += "\n" + n.Summary
	}
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return err
	}
	return postJSON(ctx, s.client, s.url, body)
}

func (s *Slack) Name() string { return "slack" }
