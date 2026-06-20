// Package api implements the FleetService gRPC server: the agent-facing control
// plane. It is deliberately thin — it validates requests, delegates state to the
// store, runs each reported alert through cross-host correlation, and serves the
// versioned ruleset. Transport security (mTLS) is configured by the caller in
// cmd/argus-server; this layer assumes an authenticated peer.
package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/argus-edr/argus/internal/fleet/fleetpb"
	"github.com/argus-edr/argus/server/correlate"
	"github.com/argus-edr/argus/server/ruleset"
	"github.com/argus-edr/argus/server/store"
)

// Deps are the collaborators a Service drives. Store and Rules are required;
// Correlator, OnSignal, Logger and Clock have safe defaults.
type Deps struct {
	Store      store.Store
	Rules      *ruleset.Provider
	Correlator *correlate.CrossHost
	// Token, when non-empty, is the shared secret an agent must present to
	// enroll. Empty means open enrollment, for development only.
	Token string
	// OnSignal is called for each cross-host signal; OnAlert for each persisted
	// alert. Both feed the admin console (the latter drives the live SSE feed).
	OnSignal func(correlate.Signal)
	OnAlert  func(store.AlertRecord)
	Logger   *slog.Logger
	Clock    func() time.Time
}

// Service is the FleetServiceServer backed by a store, a rule provider and the
// cross-host correlator.
type Service struct {
	fleetpb.UnimplementedFleetServiceServer
	store      store.Store
	rules      *ruleset.Provider
	correlator *correlate.CrossHost
	token      string
	onSignal   func(correlate.Signal)
	onAlert    func(store.AlertRecord)
	logger     *slog.Logger
	clock      func() time.Time
}

// New builds a Service, filling in defaults for the optional dependencies.
func New(deps Deps) *Service {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	onSignal := deps.OnSignal
	if onSignal == nil {
		onSignal = func(correlate.Signal) {}
	}
	onAlert := deps.OnAlert
	if onAlert == nil {
		onAlert = func(store.AlertRecord) {}
	}
	clock := deps.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		store:      deps.Store,
		rules:      deps.Rules,
		correlator: deps.Correlator,
		token:      deps.Token,
		onSignal:   onSignal,
		onAlert:    onAlert,
		logger:     logger,
		clock:      clock,
	}
}

// Enroll registers an agent and returns its assigned id plus the current rules
// version, which the agent reports back on every heartbeat to detect drift.
func (s *Service) Enroll(ctx context.Context, req *fleetpb.EnrollRequest) (*fleetpb.EnrollResponse, error) {
	if s.token != "" && req.GetEnrollmentToken() != s.token {
		s.logger.Warn("enrollment rejected", "host", req.GetHostname(), "peer", peerCommonName(ctx))
		return nil, status.Error(codes.PermissionDenied, "invalid enrollment token")
	}
	if req.GetHostname() == "" {
		return nil, status.Error(codes.InvalidArgument, "hostname is required")
	}
	agent := s.store.Enroll(req.GetHostname(), req.GetAgentVersion(), req.GetKernel(), peerFingerprint(ctx))
	s.logger.Info("agent enrolled",
		"agent", agent.ID, "host", agent.Hostname, "version", agent.Version,
		"kernel", agent.Kernel, "peer", peerCommonName(ctx))
	return &fleetpb.EnrollResponse{AgentId: agent.ID, RulesVersion: s.rules.Version()}, nil
}

// authorizeIdentity confirms the request's agent id is enrolled and that the
// calling certificate is the one it enrolled with. This is what stops any holder
// of a valid fleet certificate from acting as another agent — impersonating it on
// heartbeats, draining its command queue, or filing alerts under its name.
func (s *Service) authorizeIdentity(agentID, fingerprint string) (store.Agent, error) {
	agent, ok := s.store.Get(agentID)
	if !ok {
		return store.Agent{}, status.Errorf(codes.NotFound, "unknown agent %q: re-enroll", agentID)
	}
	if agent.CertFingerprint != "" && agent.CertFingerprint != fingerprint {
		s.logger.Warn("agent identity mismatch: certificate does not match the enrolled agent",
			"agent", agentID, "host", agent.Hostname)
		return store.Agent{}, status.Error(codes.PermissionDenied, "client certificate does not match the enrolled agent")
	}
	return agent, nil
}

// Heartbeat records the agent's liveness and counters and returns any queued
// commands. When the agent's ruleset is stale it prepends an UPDATE_RULES
// command carrying the current version, so a drifted agent always re-syncs even
// if no operator queued anything.
func (s *Service) Heartbeat(ctx context.Context, req *fleetpb.HeartbeatRequest) (*fleetpb.HeartbeatResponse, error) {
	if _, err := s.authorizeIdentity(req.GetAgentId(), peerFingerprint(ctx)); err != nil {
		return nil, err
	}
	stats := store.Stats{
		EventsProcessed: req.GetEventsProcessed(),
		Alerts:          req.GetAlerts(),
		Incidents:       req.GetIncidents(),
		RulesVersion:    req.GetRulesVersion(),
	}
	agent, ok := s.store.Heartbeat(req.GetAgentId(), stats)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unknown agent %q: re-enroll", req.GetAgentId())
	}

	commands := s.store.DrainCommands(agent.ID)
	if current := s.rules.Version(); req.GetRulesVersion() != current {
		commands = append([]store.Command{{Kind: cmdUpdateRules, Argument: current}}, commands...)
	}
	return &fleetpb.HeartbeatResponse{Commands: toProtoCommands(commands)}, nil
}

// ReportAlerts consumes the agent's stream of alerts and incidents, persisting
// each and folding it into cross-host correlation. It acks the count when the
// agent closes the stream.
func (s *Service) ReportAlerts(stream grpc.ClientStreamingServer[fleetpb.AlertReport, fleetpb.ReportAck]) error {
	fingerprint := peerFingerprint(stream.Context())
	var authorizedAgent string
	var received uint64
	for {
		report, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&fleetpb.ReportAck{Received: received})
		}
		if err != nil {
			return err
		}
		// A stream belongs to one agent: authorize the first report's id against
		// the calling certificate, then require every report to carry that id, so
		// alerts cannot be filed under another agent's name.
		if authorizedAgent == "" {
			if _, err := s.authorizeIdentity(report.GetAgentId(), fingerprint); err != nil {
				return err
			}
			authorizedAgent = report.GetAgentId()
		} else if report.GetAgentId() != authorizedAgent {
			return status.Error(codes.PermissionDenied, "all alerts in a stream must come from the enrolled agent")
		}
		record := recordFromReport(report)
		s.store.RecordAlert(record)
		s.onAlert(record)
		if s.correlator != nil {
			for _, signal := range s.correlator.Observe(record) {
				s.logger.Warn("fleet signal",
					"kind", signal.Kind, "key", signal.Key, "hosts", len(signal.Hosts), "summary", signal.Summary)
				s.onSignal(signal)
			}
		}
		received++
	}
}

// GetRules returns the current ruleset, or signals unchanged when the agent's
// known version already matches.
func (s *Service) GetRules(_ context.Context, req *fleetpb.RulesRequest) (*fleetpb.RulesResponse, error) {
	version, files := s.rules.Bundle()
	if req.GetKnownVersion() == version {
		return &fleetpb.RulesResponse{Version: version, Unchanged: true}, nil
	}
	out := make([]*fleetpb.RuleFile, len(files))
	for i, file := range files {
		out[i] = &fleetpb.RuleFile{Name: file.Name, Content: file.Content}
	}
	return &fleetpb.RulesResponse{Version: version, Files: out}, nil
}
