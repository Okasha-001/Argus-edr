package api

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/argus-edr/argus/internal/fleet/fleetpb"
	"github.com/argus-edr/argus/server/store"
)

// Command kinds, named to match the proto Command.Kind enum so a store command
// round-trips through the enum's value map without a hand-maintained switch.
const (
	cmdUpdateRules     = "UPDATE_RULES"
	cmdSetResponseMode = "SET_RESPONSE_MODE"
	cmdKillProcess     = "KILL_PROCESS"
	cmdQuarantine      = "QUARANTINE"
)

func toProtoCommands(commands []store.Command) []*fleetpb.Command {
	out := make([]*fleetpb.Command, 0, len(commands))
	for _, command := range commands {
		kind := fleetpb.Command_KIND_UNSPECIFIED
		if value, ok := fleetpb.Command_Kind_value[command.Kind]; ok {
			kind = fleetpb.Command_Kind(value)
		}
		out = append(out, &fleetpb.Command{Kind: kind, Argument: command.Argument})
	}
	return out
}

func recordFromReport(report *fleetpb.AlertReport) store.AlertRecord {
	record := store.AlertRecord{
		AgentID:           report.GetAgentId(),
		Hostname:          report.GetHostname(),
		RuleID:            report.GetRuleId(),
		RuleName:          report.GetRuleName(),
		Severity:          report.GetSeverity(),
		TechniqueID:       report.GetTechniqueId(),
		TechniqueName:     report.GetTechniqueName(),
		PID:               report.GetPid(),
		ProcessName:       report.GetProcessName(),
		ProcessExecutable: report.GetProcessExecutable(),
		DestinationIP:     report.GetDestinationIp(),
		RiskScore:         int(report.GetRiskScore()),
		IsIncident:        report.GetIsIncident(),
	}
	if ts := report.GetTimestamp(); ts != nil {
		record.Time = ts.AsTime()
	}
	return record
}

// peerLeaf returns the mTLS client's leaf certificate, or false for a non-TLS
// peer (in-process tests).
func peerLeaf(ctx context.Context) (*x509.Certificate, bool) {
	info, ok := peer.FromContext(ctx)
	if !ok {
		return nil, false
	}
	tlsInfo, ok := info.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, false
	}
	return tlsInfo.State.PeerCertificates[0], true
}

// peerCommonName returns the common name from the mTLS client certificate, used
// for audit logging. It is empty for non-TLS peers (in-process tests).
func peerCommonName(ctx context.Context) string {
	if cert, ok := peerLeaf(ctx); ok {
		return cert.Subject.CommonName
	}
	return ""
}

// peerFingerprint returns the SHA-256 hex of the mTLS client certificate, the
// stable identity an agent is bound to at enrollment. It is empty for non-TLS
// peers. Pinning the whole certificate (not just the common name) means two
// certs with the same name are still distinct identities.
func peerFingerprint(ctx context.Context) string {
	cert, ok := peerLeaf(ctx)
	if !ok {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
