package fleet

import (
	"github.com/argus-edr/argus/internal/fleet/fleetpb"
	"github.com/argus-edr/argus/internal/model"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AlertReportFromAlert flattens an agent-side alert into the wire form the
// control plane stores and correlates across the fleet. agentID and hostname
// identify the reporting agent; both come from enrollment, not the alert.
func AlertReportFromAlert(agentID, hostname string, alert *model.Alert) *fleetpb.AlertReport {
	report := &fleetpb.AlertReport{
		AgentId:       agentID,
		Hostname:      hostname,
		Timestamp:     timestamppb.New(alert.Timestamp),
		RuleId:        alert.RuleID,
		RuleName:      alert.RuleName,
		Severity:      alert.Severity.String(),
		TechniqueId:   alert.Technique.ID,
		TechniqueName: alert.Technique.Name,
		RiskScore:     int32(alert.RiskScore),
	}
	if alert.Event != nil {
		report.Pid = alert.Event.Process.PID
		report.ProcessName = alert.Event.Process.Name
		report.ProcessExecutable = alert.Event.Process.Executable
		report.DestinationIp = alert.Event.Network.DstIP
	}
	return report
}

// AlertReportFromIncident reports a correlated incident as a high-signal record
// flagged is_incident. Carrying the lead technique lets the control plane fold
// incidents into the same cross-host correlation as raw alerts.
func AlertReportFromIncident(agentID, hostname string, incident *model.Incident) *fleetpb.AlertReport {
	report := &fleetpb.AlertReport{
		AgentId:    agentID,
		Hostname:   hostname,
		Timestamp:  timestamppb.New(incident.LastSeen),
		RuleId:     incident.ID,
		RuleName:   incident.Summary,
		Severity:   model.SeverityCritical.String(),
		RiskScore:  int32(incident.RiskScore),
		IsIncident: true,
	}
	if len(incident.Techniques) > 0 {
		report.TechniqueId = incident.Techniques[0]
	}
	return report
}
