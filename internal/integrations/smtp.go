package integrations

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
)

// SMTP delivers notifications by email. Auth is optional — an internal relay that
// accepts unauthenticated mail from the host is common and fully self-hosted.
type SMTP struct {
	addr string // host:port
	from string
	to   []string
	auth smtp.Auth // nil = no authentication
	send func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// NewSMTP returns an email notifier, or nil when addr/from/to are not all set.
// A non-empty username enables PLAIN auth against the server's host.
func NewSMTP(addr, from string, to []string, username, password string) *SMTP {
	if addr == "" || from == "" || len(to) == 0 {
		return nil
	}
	var auth smtp.Auth
	if username != "" {
		host := addr
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			host = addr[:i]
		}
		auth = smtp.PlainAuth("", username, password, host)
	}
	return &SMTP{addr: addr, from: from, to: to, auth: auth, send: smtp.SendMail}
}

func (s *SMTP) Notify(ctx context.Context, n Notification) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	subject := "[ARGUS] " + strings.ToUpper(n.Severity) + " " + n.Title
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n%s\r\n",
		s.from, strings.Join(s.to, ", "), subject, n.textLine(), n.Summary)
	if err := s.send(s.addr, s.auth, s.from, s.to, []byte(msg)); err != nil {
		return fmt.Errorf("send mail: %w", err)
	}
	return nil
}

func (s *SMTP) Name() string { return "smtp" }
