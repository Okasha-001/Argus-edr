package fleet

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/argus-edr/argus/internal/fleet/fleetpb"
)

// ClientConfig configures the agent's connection to the control plane.
type ClientConfig struct {
	ServerAddress   string
	ServerName      string
	CAFile          string
	CertFile        string
	KeyFile         string
	Hostname        string
	AgentVersion    string
	Kernel          string
	EnrollmentToken string
}

// Stats are the counters an agent reports on each heartbeat.
type Stats struct {
	EventsProcessed uint64
	Alerts          uint64
	Incidents       uint64
	RulesVersion    string
}

// Command is an instruction the control plane returns on a heartbeat. Kind is
// the proto enum's name (e.g. "UPDATE_RULES"); the caller interprets Argument
// per kind.
type Command struct {
	Kind     string
	Argument string
}

// EnrollResult is what the server assigns at enrollment.
type EnrollResult struct {
	AgentID      string
	RulesVersion string
}

// RuleFile is one fetched rule file: its base name and raw YAML bytes.
type RuleFile struct {
	Name    string
	Content []byte
}

// Rules is the result of a GetRules call. When Unchanged is true the agent's
// known version already matched and Files is empty.
type Rules struct {
	Version   string
	Unchanged bool
	Files     []RuleFile
}

// Client is the agent-side handle to the FleetService over mTLS.
type Client struct {
	conn         *grpc.ClientConn
	rpc          fleetpb.FleetServiceClient
	hostname     string
	agentVersion string
	kernel       string
	token        string
}

// Dial establishes the mTLS connection to the control plane. The connection is
// lazy; the first RPC drives the handshake.
func Dial(cfg ClientConfig) (*Client, error) {
	tlsConfig, err := ClientTLSConfigFromFiles(cfg.CAFile, cfg.CertFile, cfg.KeyFile, cfg.ServerName)
	if err != nil {
		return nil, fmt.Errorf("fleet tls config: %w", err)
	}
	conn, err := grpc.NewClient(cfg.ServerAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.ServerAddress, err)
	}
	return &Client{
		conn:         conn,
		rpc:          fleetpb.NewFleetServiceClient(conn),
		hostname:     cfg.Hostname,
		agentVersion: cfg.AgentVersion,
		kernel:       cfg.Kernel,
		token:        cfg.EnrollmentToken,
	}, nil
}

// Enroll registers the agent and returns its assigned id and the fleet's current
// rules version.
func (c *Client) Enroll(ctx context.Context) (EnrollResult, error) {
	resp, err := c.rpc.Enroll(ctx, &fleetpb.EnrollRequest{
		Hostname:        c.hostname,
		AgentVersion:    c.agentVersion,
		Kernel:          c.kernel,
		EnrollmentToken: c.token,
	})
	if err != nil {
		return EnrollResult{}, fmt.Errorf("enroll: %w", err)
	}
	return EnrollResult{AgentID: resp.GetAgentId(), RulesVersion: resp.GetRulesVersion()}, nil
}

// Heartbeat reports liveness and counters and returns any commands the control
// plane has queued for this agent.
func (c *Client) Heartbeat(ctx context.Context, agentID string, stats Stats) ([]Command, error) {
	resp, err := c.rpc.Heartbeat(ctx, &fleetpb.HeartbeatRequest{
		AgentId:         agentID,
		EventsProcessed: stats.EventsProcessed,
		Alerts:          stats.Alerts,
		Incidents:       stats.Incidents,
		RulesVersion:    stats.RulesVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("heartbeat: %w", err)
	}
	commands := make([]Command, 0, len(resp.GetCommands()))
	for _, command := range resp.GetCommands() {
		commands = append(commands, Command{Kind: command.GetKind().String(), Argument: command.GetArgument()})
	}
	return commands, nil
}

// FetchRules pulls the fleet ruleset unless knownVersion is already current.
func (c *Client) FetchRules(ctx context.Context, agentID, knownVersion string) (Rules, error) {
	resp, err := c.rpc.GetRules(ctx, &fleetpb.RulesRequest{AgentId: agentID, KnownVersion: knownVersion})
	if err != nil {
		return Rules{}, fmt.Errorf("get rules: %w", err)
	}
	if resp.GetUnchanged() {
		return Rules{Version: resp.GetVersion(), Unchanged: true}, nil
	}
	files := make([]RuleFile, 0, len(resp.GetFiles()))
	for _, file := range resp.GetFiles() {
		files = append(files, RuleFile{Name: file.GetName(), Content: file.GetContent()})
	}
	return Rules{Version: resp.GetVersion(), Files: files}, nil
}

// Report streams a batch of alerts to the control plane and returns the count
// the server acknowledged. It opens a fresh stream per call and waits for the
// ack, so the reports are durably received when it returns. The Reporter is the
// continuous, fire-and-forget path for the live agent.
func (c *Client) Report(ctx context.Context, reports ...*fleetpb.AlertReport) (uint64, error) {
	stream, err := c.rpc.ReportAlerts(ctx)
	if err != nil {
		return 0, fmt.Errorf("open report stream: %w", err)
	}
	for _, report := range reports {
		if err := stream.Send(report); err != nil {
			return 0, fmt.Errorf("send report: %w", err)
		}
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		return 0, fmt.Errorf("close report stream: %w", err)
	}
	return ack.GetReceived(), nil
}

// Close tears down the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
