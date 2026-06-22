package integrations

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Syslog sends an RFC 3164 line to a remote syslog collector over UDP or TCP. It
// is written directly to the network (not via the platform-specific log/syslog
// package) so it works the same everywhere and targets a central collector — the
// usual deployment. The source host field is the neutral "argus" rather than the
// real hostname, keeping machine identity out of the wire format.
type Syslog struct {
	network string // "udp" or "tcp"
	addr    string // host:port, e.g. 203.0.113.5:514
	dial    func(network, addr string) (net.Conn, error)
}

// NewSyslog returns a syslog notifier, or nil when addr is empty. network
// defaults to udp.
func NewSyslog(network, addr string) *Syslog {
	if addr == "" {
		return nil
	}
	if network == "" {
		network = "udp"
	}
	return &Syslog{network: network, addr: addr, dial: net.Dial}
}

// syslogSeverity maps an alert severity to the numeric syslog severity that, with
// the local0 facility, forms the RFC 3164 priority value.
var syslogSeverity = map[string]int{"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}

func (s *Syslog) Notify(_ context.Context, n Notification) error {
	severity, ok := syslogSeverity[strings.ToLower(n.Severity)]
	if !ok {
		severity = 5 // notice
	}
	const localFacility = 16
	priority := localFacility*8 + severity
	line := fmt.Sprintf("<%d>%s argus argus: %s", priority, time.Now().Format(time.Stamp), n.textLine())

	conn, err := s.dial(s.network, s.addr)
	if err != nil {
		return fmt.Errorf("dial syslog: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(line)); err != nil {
		return fmt.Errorf("write syslog: %w", err)
	}
	return nil
}

func (s *Syslog) Name() string { return "syslog" }
