package api_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/argus-edr/argus/internal/fleet"
	"github.com/argus-edr/argus/internal/fleet/fleetpb"
	"github.com/argus-edr/argus/server/api"
	"github.com/argus-edr/argus/server/correlate"
	"github.com/argus-edr/argus/server/ruleset"
	"github.com/argus-edr/argus/server/store"
)

const ruleA = `- id: R-9001
  name: Test rule A
  severity: high
  technique:
    id: T1059
    name: Command and Scripting Interpreter
    tactic: execution
  match:
    all:
      - { field: event.type, op: eq, value: exec }
`

const ruleB = `- id: R-9002
  name: Test rule B
  severity: medium
  technique:
    id: T1071
    name: Application Layer Protocol
    tactic: command-and-control
  match:
    all:
      - { field: event.type, op: eq, value: connect }
`

// harness is a running control plane over real mTLS plus the certs an agent
// needs to connect to it.
type harness struct {
	addr     string
	certDir  string
	certs    *fleet.DevCerts
	provider *ruleset.Provider
	store    store.Store
	signals  func() []correlate.Signal
}

func startServer(t *testing.T, token string) *harness {
	t.Helper()
	dir := t.TempDir()

	certs, err := fleet.GenerateDevCerts("argus-server")
	if err != nil {
		t.Fatalf("generate certs: %v", err)
	}
	if err := fleet.WriteDevCerts(dir, certs); err != nil {
		t.Fatalf("write certs: %v", err)
	}

	rulesDir := filepath.Join(dir, "rules")
	writeFiles(t, rulesDir, map[string]string{"00-a.yaml": ruleA, "10-b.yaml": ruleB})
	provider, err := ruleset.NewProvider(rulesDir)
	if err != nil {
		t.Fatalf("rule provider: %v", err)
	}

	memStore := store.NewMemory()
	correlator := correlate.NewCrossHost(time.Minute, 2)
	var mu sync.Mutex
	var signals []correlate.Signal

	service := api.New(api.Deps{
		Store:      memStore,
		Rules:      provider,
		Correlator: correlator,
		Token:      token,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnSignal: func(signal correlate.Signal) {
			mu.Lock()
			signals = append(signals, signal)
			mu.Unlock()
		},
	})

	serverTLS, err := fleet.ServerTLSConfig(certs.CA.Cert, certs.Server.Cert, certs.Server.Key)
	if err != nil {
		t.Fatalf("server tls: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	fleetpb.RegisterFleetServiceServer(grpcServer, service)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)

	return &harness{
		addr:     listener.Addr().String(),
		certDir:  dir,
		certs:    certs,
		provider: provider,
		store:    memStore,
		signals: func() []correlate.Signal {
			mu.Lock()
			defer mu.Unlock()
			return append([]correlate.Signal(nil), signals...)
		},
	}
}

func (h *harness) dial(t *testing.T, hostname, token string) *fleet.Client {
	t.Helper()
	client, err := fleet.Dial(fleet.ClientConfig{
		ServerAddress:   h.addr,
		ServerName:      "argus-server",
		CAFile:          filepath.Join(h.certDir, "ca.pem"),
		CertFile:        filepath.Join(h.certDir, "agent.pem"),
		KeyFile:         filepath.Join(h.certDir, "agent-key.pem"),
		Hostname:        hostname,
		AgentVersion:    "test",
		Kernel:          "6.8.0",
		EnrollmentToken: token,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// dialWith connects using a caller-supplied client certificate instead of the
// shared dev cert, so a test can present a distinct identity to the server.
func (h *harness) dialWith(t *testing.T, hostname string, cert fleet.PEMPair) *fleet.Client {
	t.Helper()
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"ca.pem":        string(h.certs.CA.Cert),
		"agent.pem":     string(cert.Cert),
		"agent-key.pem": string(cert.Key),
	})
	client, err := fleet.Dial(fleet.ClientConfig{
		ServerAddress: h.addr, ServerName: "argus-server",
		CAFile:   filepath.Join(dir, "ca.pem"),
		CertFile: filepath.Join(dir, "agent.pem"),
		KeyFile:  filepath.Join(dir, "agent-key.pem"),
		Hostname: hostname, AgentVersion: "test", Kernel: "6.8.0",
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestHeartbeatRejectsImpersonationByAnotherCert(t *testing.T) {
	h := startServer(t, "")
	ctx := context.Background()

	// Agent A enrolls with the shared dev cert.
	victim := h.dial(t, "web-01", "")
	victimEnroll, err := victim.Enroll(ctx)
	if err != nil {
		t.Fatalf("enroll victim: %v", err)
	}

	// A different host with its own certificate (distinct key => distinct identity).
	attackerCert, err := fleet.GenerateAgentCert("attacker", h.certs.CA.Cert, h.certs.CA.Key)
	if err != nil {
		t.Fatalf("mint attacker cert: %v", err)
	}
	attacker := h.dialWith(t, "attacker-01", attackerCert)
	if _, err := attacker.Enroll(ctx); err != nil {
		t.Fatalf("enroll attacker: %v", err)
	}

	// The attacker's cert is CA-valid, but it must not be able to heartbeat as the
	// victim agent.
	_, err = attacker.Heartbeat(ctx, victimEnroll.AgentID, fleet.Stats{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("impersonation not blocked: err = %v, want PermissionDenied", err)
	}

	// The victim, presenting its own cert, still works.
	if _, err := victim.Heartbeat(ctx, victimEnroll.AgentID, fleet.Stats{RulesVersion: h.provider.Version()}); err != nil {
		t.Fatalf("legitimate heartbeat failed: %v", err)
	}
}

func TestReportRejectsImpersonationByAnotherCert(t *testing.T) {
	h := startServer(t, "")
	ctx := context.Background()

	victim := h.dial(t, "web-01", "")
	victimEnroll, err := victim.Enroll(ctx)
	if err != nil {
		t.Fatalf("enroll victim: %v", err)
	}

	attackerCert, err := fleet.GenerateAgentCert("attacker", h.certs.CA.Cert, h.certs.CA.Key)
	if err != nil {
		t.Fatalf("mint attacker cert: %v", err)
	}
	attacker := h.dialWith(t, "attacker-01", attackerCert)
	if _, err := attacker.Enroll(ctx); err != nil {
		t.Fatalf("enroll attacker: %v", err)
	}

	// Filing alerts under the victim's id with the attacker's cert is refused.
	_, err = attacker.Report(ctx, &fleetpb.AlertReport{
		AgentId: victimEnroll.AgentID, Hostname: "web-01", TechniqueId: "T1059", RuleId: "R-9001",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("alert impersonation not blocked: err = %v, want PermissionDenied", err)
	}
}

func TestEnrollRejectsBadToken(t *testing.T) {
	h := startServer(t, "s3cr3t")
	client := h.dial(t, "web-01", "wrong")
	if _, err := client.Enroll(context.Background()); err == nil {
		t.Fatal("expected enrollment to be rejected for a bad token")
	}
}

func TestEnrollAndHeartbeatLifecycle(t *testing.T) {
	h := startServer(t, "s3cr3t")
	ctx := context.Background()
	client := h.dial(t, "web-01", "s3cr3t")

	enrolled, err := client.Enroll(ctx)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if enrolled.AgentID == "" {
		t.Fatal("enroll returned an empty agent id")
	}
	if enrolled.RulesVersion != h.provider.Version() {
		t.Errorf("rules version = %q, want %q", enrolled.RulesVersion, h.provider.Version())
	}

	// A heartbeat that reports a stale ruleset must be told to update.
	commands, err := client.Heartbeat(ctx, enrolled.AgentID, fleet.Stats{RulesVersion: ""})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if len(commands) != 1 || commands[0].Kind != "UPDATE_RULES" {
		t.Fatalf("commands = %+v, want one UPDATE_RULES", commands)
	}
	if commands[0].Argument != h.provider.Version() {
		t.Errorf("UPDATE_RULES argument = %q, want %q", commands[0].Argument, h.provider.Version())
	}

	// Once current, the heartbeat carries no commands.
	commands, err = client.Heartbeat(ctx, enrolled.AgentID, fleet.Stats{RulesVersion: h.provider.Version()})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if len(commands) != 0 {
		t.Errorf("expected no commands when current, got %+v", commands)
	}

	if _, err := client.Heartbeat(ctx, "not-enrolled", fleet.Stats{}); err == nil {
		t.Fatal("expected heartbeat from an unknown agent to fail")
	}
}

func TestGetRulesChangedThenUnchanged(t *testing.T) {
	h := startServer(t, "")
	ctx := context.Background()
	client := h.dial(t, "web-01", "")
	enrolled, err := client.Enroll(ctx)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	rules, err := client.FetchRules(ctx, enrolled.AgentID, "")
	if err != nil {
		t.Fatalf("fetch rules: %v", err)
	}
	if rules.Unchanged {
		t.Fatal("first fetch should return the ruleset, not unchanged")
	}
	if len(rules.Files) != 2 {
		t.Fatalf("got %d rule files, want 2", len(rules.Files))
	}
	if rules.Version != h.provider.Version() {
		t.Errorf("version = %q, want %q", rules.Version, h.provider.Version())
	}

	current, err := client.FetchRules(ctx, enrolled.AgentID, rules.Version)
	if err != nil {
		t.Fatalf("fetch rules: %v", err)
	}
	if !current.Unchanged {
		t.Error("fetch with the current version should report unchanged")
	}
}

func TestReportAlertsDrivesCrossHostCorrelation(t *testing.T) {
	h := startServer(t, "")
	ctx := context.Background()

	web := h.dial(t, "web-01", "")
	webEnroll, err := web.Enroll(ctx)
	if err != nil {
		t.Fatalf("enroll web: %v", err)
	}
	received, err := web.Report(ctx, &fleetpb.AlertReport{
		AgentId: webEnroll.AgentID, Hostname: "web-01", TechniqueId: "T1059", RuleId: "R-9001",
	})
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if received != 1 {
		t.Errorf("received = %d, want 1", received)
	}
	if got := h.signals(); len(got) != 0 {
		t.Fatalf("one host should not trigger a signal, got %+v", got)
	}

	db := h.dial(t, "db-01", "")
	dbEnroll, err := db.Enroll(ctx)
	if err != nil {
		t.Fatalf("enroll db: %v", err)
	}
	if _, err := db.Report(ctx, &fleetpb.AlertReport{
		AgentId: dbEnroll.AgentID, Hostname: "db-01", TechniqueId: "T1059", RuleId: "R-9001",
	}); err != nil {
		t.Fatalf("report: %v", err)
	}

	signals := h.signals()
	if len(signals) != 1 {
		t.Fatalf("a second host on the same technique should fire one signal, got %d", len(signals))
	}
	if signals[0].Kind != correlate.KindLateralMovement || signals[0].Key != "T1059" {
		t.Errorf("signal = %+v, want lateral-movement on T1059", signals[0])
	}
	if len(h.store.RecentAlerts(10)) != 2 {
		t.Errorf("store should hold both reported alerts")
	}
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
