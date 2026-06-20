package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/argus-edr/argus/internal/model"
)

// StdoutSink writes to a writer (stdout by default). "ecs" emits one ECS JSON
// document per line; "pretty" emits a compact human-readable summary.
type StdoutSink struct {
	mu     sync.Mutex
	writer *bufio.Writer
	ecs    bool
}

// NewStdout builds a stdout sink. format is "ecs" or "pretty".
func NewStdout(w io.Writer, format string) *StdoutSink {
	return &StdoutSink{writer: bufio.NewWriter(w), ecs: format != "pretty"}
}

func (s *StdoutSink) WriteEvent(event *model.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ecs {
		return s.writeJSON(event.ECS())
	}
	return s.writeLine(prettyEvent(event))
}

func (s *StdoutSink) WriteAlert(alert *model.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ecs {
		return s.writeJSON(alert.ECS())
	}
	return s.writeLine(prettyAlert(alert))
}

func (s *StdoutSink) WriteIncident(incident *model.Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ecs {
		return s.writeJSON(incident.ECS())
	}
	return s.writeLine(prettyIncident(incident))
}

func (s *StdoutSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writer.Flush()
}

func (s *StdoutSink) Close() error {
	return s.Flush()
}

func (s *StdoutSink) writeJSON(doc map[string]any) error {
	line, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return s.writeLine(string(line))
}

func (s *StdoutSink) writeLine(line string) error {
	if _, err := s.writer.WriteString(line + "\n"); err != nil {
		return err
	}
	return s.writer.Flush()
}

func prettyEvent(event *model.Event) string {
	return fmt.Sprintf("%s %-8s pid=%-7d %-16s %s",
		event.Timestamp.Format("15:04:05.000"),
		event.Action, event.Process.PID, event.Process.Name, eventDetail(event))
}

func eventDetail(event *model.Event) string {
	switch event.Type {
	case model.EventExec, model.EventExecBlocked:
		return event.Process.CommandLine
	case model.EventConnect, model.EventAccept:
		return fmt.Sprintf("%s:%d -> %s:%d", event.Network.SrcIP, event.Network.SrcPort,
			event.Network.DstIP, event.Network.DstPort)
	default:
		if event.File.Target != "" {
			return event.File.Path + " -> " + event.File.Target
		}
		return event.File.Path
	}
}

func prettyAlert(alert *model.Alert) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ALERT [%s] %s %s", strings.ToUpper(alert.Severity.String()), alert.RuleID, alert.RuleName)
	if alert.Technique.ID != "" {
		fmt.Fprintf(&b, " (%s %s)", alert.Technique.ID, alert.Technique.Name)
	}
	fmt.Fprintf(&b, " — pid=%d %s", alert.Event.Process.PID, alert.Event.Process.Name)
	return b.String()
}

func prettyIncident(incident *model.Incident) string {
	return fmt.Sprintf("INCIDENT [risk %d] %s — %s (techniques: %s)",
		incident.RiskScore, incident.ID, incident.Summary, strings.Join(incident.Techniques, ", "))
}
