// Package integrations sends ARGUS notifications to the outside world: a generic
// webhook, Slack/Mattermost, email (SMTP), and syslog. Every integration is
// optional and self-hosted-friendly — none is required and none is a paid
// service. They are the only components that deliberately make an outbound
// connection, and only to an endpoint the operator configured, which keeps the
// platform's zero-phone-home promise intact (see docs/GOVERNANCE.md).
package integrations

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Notification is one alert worth telling a human (or another system) about. It
// carries no machine- or developer-specific data beyond what the alert already
// holds.
type Notification struct {
	Title     string
	Summary   string
	Severity  string
	Host      string
	RuleID    string
	Technique string
}

// Notifier delivers a Notification to one destination.
type Notifier interface {
	Notify(ctx context.Context, n Notification) error
	Name() string
}

// Multi fans a notification out to several notifiers. One failing does not stop
// the others; the combined error names every destination that failed.
type Multi struct {
	notifiers []Notifier
}

// NewMulti groups notifiers. Nil entries are dropped, so callers can build the
// list conditionally (a destination is added only when configured).
func NewMulti(notifiers ...Notifier) *Multi {
	live := make([]Notifier, 0, len(notifiers))
	for _, n := range notifiers {
		if n != nil {
			live = append(live, n)
		}
	}
	return &Multi{notifiers: live}
}

// Len reports how many destinations are configured; zero means notifications are
// effectively disabled.
func (m *Multi) Len() int { return len(m.notifiers) }

// Names lists the configured destinations, for status display.
func (m *Multi) Names() []string {
	names := make([]string, len(m.notifiers))
	for i, n := range m.notifiers {
		names[i] = n.Name()
	}
	return names
}

func (m *Multi) Notify(ctx context.Context, n Notification) error {
	var errs []error
	for _, notifier := range m.notifiers {
		if err := notifier.Notify(ctx, n); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", notifier.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func (m *Multi) Name() string { return "multi(" + strings.Join(m.Names(), ",") + ")" }

// textLine is the one-line plain-text rendering used by the simpler transports
// (Slack falls back to it, syslog uses it verbatim).
func (n Notification) textLine() string {
	parts := []string{"[ARGUS]"}
	if n.Severity != "" {
		parts = append(parts, strings.ToUpper(n.Severity))
	}
	parts = append(parts, n.Title)
	if n.Host != "" {
		parts = append(parts, "host="+n.Host)
	}
	if n.RuleID != "" {
		parts = append(parts, n.RuleID)
	}
	if n.Technique != "" {
		parts = append(parts, n.Technique)
	}
	return strings.Join(parts, " ")
}
