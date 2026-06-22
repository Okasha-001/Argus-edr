package integrations

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strings"
	"testing"
)

var sample = Notification{Title: "Reverse shell", Summary: "bash under nginx", Severity: "critical", Host: "web-01", RuleID: "R-0007", Technique: "T1059"}

func TestWebhookPostsJSON(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = string(body)
	}))
	defer srv.Close()

	if err := NewWebhook(srv.URL).Notify(context.Background(), sample); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if !strings.Contains(got, `"rule_id":"R-0007"`) || !strings.Contains(got, `"severity":"critical"`) {
		t.Errorf("webhook payload = %s", got)
	}
}

func TestWebhookNonExistentURLDisabled(t *testing.T) {
	if NewWebhook("") != nil {
		t.Error("an empty URL must yield a nil (disabled) notifier")
	}
}

func TestSlackPostsText(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = string(body)
	}))
	defer srv.Close()

	if err := NewSlack(srv.URL).Notify(context.Background(), sample); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if !strings.Contains(got, "Reverse shell") || !strings.Contains(got, "web-01") {
		t.Errorf("slack payload = %s", got)
	}
}

func TestWebhookFailsOnErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := NewWebhook(srv.URL).Notify(context.Background(), sample); err == nil {
		t.Error("a 500 response must be reported as a delivery failure")
	}
}

func TestSMTPBuildsMessage(t *testing.T) {
	notifier := NewSMTP("mail.example.com:25", "argus@example.com", []string{"soc@example.com"}, "", "")
	var sentMsg string
	notifier.send = func(addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
		sentMsg = string(msg)
		return nil
	}
	if err := notifier.Notify(context.Background(), sample); err != nil {
		t.Fatalf("notify: %v", err)
	}
	for _, want := range []string{"Subject: [ARGUS] CRITICAL Reverse shell", "To: soc@example.com", "R-0007"} {
		if !strings.Contains(sentMsg, want) {
			t.Errorf("message missing %q:\n%s", want, sentMsg)
		}
	}
}

func TestSyslogWritesRFC3164(t *testing.T) {
	notifier := NewSyslog("udp", "203.0.113.5:514")
	server, client := net.Pipe()
	notifier.dial = func(_, _ string) (net.Conn, error) { return client, nil }
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 256)
		n, _ := server.Read(buf)
		done <- string(buf[:n])
	}()
	if err := notifier.Notify(context.Background(), sample); err != nil {
		t.Fatalf("notify: %v", err)
	}
	line := <-done
	// local0 (16*8) + critical (2) = 130
	if !strings.HasPrefix(line, "<130>") || !strings.Contains(line, "R-0007") {
		t.Errorf("syslog line = %q", line)
	}
}

func TestMultiAggregates(t *testing.T) {
	ok := NewWebhook("http://unused")
	multi := NewMulti(ok, nil) // nil is dropped
	if multi.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (nil dropped)", multi.Len())
	}
}
