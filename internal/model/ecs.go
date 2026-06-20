package model

import "time"

// ecsVersion is the Elastic Common Schema version the projection targets.
const ecsVersion = "8.11"

var ecsCategories = map[EventType][]string{
	EventExec:        {"process"},
	EventFork:        {"process"},
	EventExit:        {"process"},
	EventExecBlocked: {"process"},
	EventOpen:        {"file"},
	EventUnlink:      {"file"},
	EventRename:      {"file"},
	EventChmod:       {"file"},
	EventConnect:     {"network"},
	EventAccept:      {"network"},
}

var ecsTypes = map[EventType][]string{
	EventExec:        {"start"},
	EventFork:        {"start"},
	EventExit:        {"end"},
	EventExecBlocked: {"denied"},
	EventOpen:        {"change"},
	EventUnlink:      {"deletion"},
	EventRename:      {"change"},
	EventChmod:       {"change"},
	EventConnect:     {"connection"},
	EventAccept:      {"connection"},
}

// ECS renders the event as an Elastic Common Schema document, the format the
// external sinks and Grafana dashboards expect.
func (e *Event) ECS() map[string]any {
	doc := map[string]any{
		"@timestamp":     e.Timestamp.UTC().Format(time.RFC3339Nano),
		"schema_version": e.SchemaVersion,
		"ecs":            map[string]any{"version": ecsVersion},
		"event": map[string]any{
			"kind":     "event",
			"action":   e.Action,
			"category": ecsCategories[e.Type],
			"type":     ecsTypes[e.Type],
		},
		"process": e.processECS(),
		"user":    map[string]any{"id": e.User.ID, "name": e.User.Name},
	}
	if e.Host != "" {
		doc["host"] = map[string]any{"name": e.Host, "os": map[string]any{"type": "linux"}}
	}
	if e.File.Path != "" {
		file := map[string]any{"path": e.File.Path}
		if e.File.Target != "" {
			file["target_path"] = e.File.Target
		}
		doc["file"] = file
	}
	e.networkECS(doc)
	if e.Container.ID != "" {
		doc["container"] = map[string]any{"id": e.Container.ID, "runtime": e.Container.Runtime}
	}
	return doc
}

func (e *Event) processECS() map[string]any {
	process := map[string]any{"pid": e.Process.PID, "name": e.Process.Name}
	if e.Process.Executable != "" {
		process["executable"] = e.Process.Executable
	}
	if e.Process.CommandLine != "" {
		process["command_line"] = e.Process.CommandLine
	}
	if e.Process.SHA256 != "" {
		process["hash"] = map[string]any{"sha256": e.Process.SHA256}
	}
	if e.Process.PPID != 0 {
		process["parent"] = map[string]any{
			"pid":        e.Process.PPID,
			"name":       e.Process.ParentName,
			"executable": e.Process.ParentExecutable,
		}
	}
	return process
}

func (e *Event) networkECS(doc map[string]any) {
	if e.Network.SrcIP != "" {
		doc["source"] = map[string]any{"ip": e.Network.SrcIP, "port": e.Network.SrcPort}
	}
	if e.Network.DstIP != "" {
		destination := map[string]any{"ip": e.Network.DstIP, "port": e.Network.DstPort}
		if e.Network.GeoCountry != "" {
			destination["geo"] = map[string]any{"country_iso_code": e.Network.GeoCountry}
		}
		doc["destination"] = destination
	}
	if e.Network.Domain != "" {
		doc["dns"] = map[string]any{"question": map[string]any{"name": e.Network.Domain}}
	}
}

// ECS renders the alert as an ECS document: the triggering event plus an `edr`
// block carrying the rule, severity, ATT&CK technique and any response taken.
func (a *Alert) ECS() map[string]any {
	doc := a.Event.ECS()
	if eventBlock, ok := doc["event"].(map[string]any); ok {
		eventBlock["kind"] = "alert"
	}

	edr := map[string]any{
		"rule":     map[string]any{"id": a.RuleID, "name": a.RuleName},
		"severity": a.Severity.String(),
		"threat": map[string]any{
			"technique": map[string]any{
				"id":     a.Technique.ID,
				"name":   a.Technique.Name,
				"tactic": a.Technique.Tactic,
			},
		},
	}
	if a.RiskScore > 0 {
		edr["risk_score"] = a.RiskScore
	}
	if a.Response != nil {
		edr["response"] = map[string]any{"action": a.Response.Action, "result": a.Response.Result}
	}
	doc["edr"] = edr
	return doc
}

// ECS renders a correlated incident as an ECS document under the
// intrusion_detection category.
func (i *Incident) ECS() map[string]any {
	return map[string]any{
		"@timestamp": i.LastSeen.UTC().Format(time.RFC3339Nano),
		"ecs":        map[string]any{"version": ecsVersion},
		"event": map[string]any{
			"kind":     "alert",
			"category": []string{"intrusion_detection"},
			"type":     []string{"info"},
		},
		"host": map[string]any{"name": i.Host},
		"edr": map[string]any{
			"incident": map[string]any{
				"id":          i.ID,
				"risk_score":  i.RiskScore,
				"status":      string(i.Status),
				"techniques":  i.Techniques,
				"rule_ids":    i.RuleIDs,
				"summary":     i.Summary,
				"process_key": i.ProcessKey,
				"first_seen":  i.FirstSeen.UTC().Format(time.RFC3339Nano),
				"last_seen":   i.LastSeen.UTC().Format(time.RFC3339Nano),
			},
		},
	}
}
