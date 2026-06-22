package model

import "path"

// OCSF projects events and alerts into the Open Cybersecurity Schema Framework
// (https://schema.ocsf.io), an open industry schema that makes ARGUS
// interoperable with any OCSF-aware data lake or SIEM. It sits beside the ECS
// projection in ecs.go; a caller picks whichever schema its downstream expects.
//
// The mapping targets OCSF 1.3.0. Every record carries the mandatory identity
// tuple (category_uid, class_uid, activity_id, type_uid = class_uid*100 +
// activity_id) and a metadata block naming the producer.

const ocsfVersion = "1.3.0"

// OCSF category and class identifiers used by the projection, taken from the
// published schema.
const (
	ocsfCatSystem   = 1 // System Activity
	ocsfCatFindings = 2 // Findings
	ocsfCatNetwork  = 4 // Network Activity

	ocsfClassFileActivity     = 1001
	ocsfClassProcessActivity  = 1007
	ocsfClassDetectionFinding = 2004
	ocsfClassNetworkActivity  = 4001
	ocsfClassDNSActivity      = 4003
)

// ocsfClass is the schema coordinates a given event type maps to.
type ocsfClass struct {
	categoryUID  int
	categoryName string
	classUID     int
	className    string
	activityID   int
	activityName string
}

var ocsfClasses = map[EventType]ocsfClass{
	EventExec:        {ocsfCatSystem, "System Activity", ocsfClassProcessActivity, "Process Activity", 1, "Launch"},
	EventFork:        {ocsfCatSystem, "System Activity", ocsfClassProcessActivity, "Process Activity", 1, "Launch"},
	EventExit:        {ocsfCatSystem, "System Activity", ocsfClassProcessActivity, "Process Activity", 2, "Terminate"},
	EventExecBlocked: {ocsfCatSystem, "System Activity", ocsfClassProcessActivity, "Process Activity", 99, "Other"},
	EventPtrace:      {ocsfCatSystem, "System Activity", ocsfClassProcessActivity, "Process Activity", 4, "Inject"},
	EventBPF:         {ocsfCatSystem, "System Activity", ocsfClassProcessActivity, "Process Activity", 99, "Other"},
	EventKmod:        {ocsfCatSystem, "System Activity", ocsfClassProcessActivity, "Process Activity", 99, "Other"},
	EventMemfd:       {ocsfCatSystem, "System Activity", ocsfClassProcessActivity, "Process Activity", 99, "Other"},
	EventMmapExec:    {ocsfCatSystem, "System Activity", ocsfClassProcessActivity, "Process Activity", 99, "Other"},
	EventPrivChange:  {ocsfCatSystem, "System Activity", ocsfClassProcessActivity, "Process Activity", 5, "Set User ID"},
	EventTamper:      {ocsfCatSystem, "System Activity", ocsfClassProcessActivity, "Process Activity", 99, "Other"},
	EventOpen:        {ocsfCatSystem, "System Activity", ocsfClassFileActivity, "File System Activity", 1, "Create"},
	EventUnlink:      {ocsfCatSystem, "System Activity", ocsfClassFileActivity, "File System Activity", 4, "Delete"},
	EventRename:      {ocsfCatSystem, "System Activity", ocsfClassFileActivity, "File System Activity", 5, "Rename"},
	EventChmod:       {ocsfCatSystem, "System Activity", ocsfClassFileActivity, "File System Activity", 6, "Set Attributes"},
	EventConnect:     {ocsfCatNetwork, "Network Activity", ocsfClassNetworkActivity, "Network Activity", 1, "Open"},
	EventAccept:      {ocsfCatNetwork, "Network Activity", ocsfClassNetworkActivity, "Network Activity", 1, "Open"},
	EventDNS:         {ocsfCatNetwork, "Network Activity", ocsfClassDNSActivity, "DNS Activity", 1, "Query"},
}

var ocsfSeverityIDs = map[Severity]int{
	SeverityLow:      2,
	SeverityMedium:   3,
	SeverityHigh:     4,
	SeverityCritical: 5,
}

var ocsfSeverityNames = map[Severity]string{
	SeverityLow:      "Low",
	SeverityMedium:   "Medium",
	SeverityHigh:     "High",
	SeverityCritical: "Critical",
}

func (e *Event) class() ocsfClass {
	if class, ok := ocsfClasses[e.Type]; ok {
		return class
	}
	return ocsfClass{ocsfCatSystem, "System Activity", ocsfClassProcessActivity, "Process Activity", 0, "Unknown"}
}

// OCSF renders the event as an OCSF class instance (schema 1.3.0).
func (e *Event) OCSF() map[string]any {
	class := e.class()
	doc := map[string]any{
		"metadata":      ocsfMetadata(),
		"time":          e.Timestamp.UnixMilli(),
		"category_uid":  class.categoryUID,
		"category_name": class.categoryName,
		"class_uid":     class.classUID,
		"class_name":    class.className,
		"activity_id":   class.activityID,
		"activity_name": class.activityName,
		"type_uid":      class.classUID*100 + class.activityID,
		"severity_id":   1, // Informational: raw telemetry, not a finding
		"severity":      "Informational",
	}
	e.ocsfActor(doc, class)
	e.ocsfFile(doc, class)
	e.ocsfNetwork(doc, class)
	e.ocsfDevice(doc)
	return doc
}

func ocsfMetadata() map[string]any {
	return map[string]any{
		"version": ocsfVersion,
		"product": map[string]any{"name": "ARGUS", "vendor_name": "argus-edr"},
	}
}

// ocsfActor places the acting process. For process activity the affected
// process is `process` and its parent is the `actor`; for file and network
// activity the acting process is the `actor`.
func (e *Event) ocsfActor(doc map[string]any, class ocsfClass) {
	switch class.classUID {
	case ocsfClassProcessActivity:
		doc["process"] = e.ocsfProcess()
		if e.Process.PPID != 0 {
			doc["actor"] = map[string]any{"process": map[string]any{
				"pid": e.Process.PPID, "name": e.Process.ParentName,
			}}
		}
	case ocsfClassFileActivity, ocsfClassNetworkActivity, ocsfClassDNSActivity:
		doc["actor"] = map[string]any{"process": e.ocsfProcess()}
	}
}

func (e *Event) ocsfProcess() map[string]any {
	process := map[string]any{"pid": e.Process.PID, "name": e.Process.Name}
	if e.Process.CommandLine != "" {
		process["cmd_line"] = e.Process.CommandLine
	}
	if file := e.ocsfProcessFile(); file != nil {
		process["file"] = file
	}
	return process
}

func (e *Event) ocsfProcessFile() map[string]any {
	if e.Process.Executable == "" && e.Process.SHA256 == "" {
		return nil
	}
	file := map[string]any{"type_id": 1, "type": "Regular File"}
	if e.Process.Executable != "" {
		file["path"] = e.Process.Executable
		file["name"] = path.Base(e.Process.Executable)
	}
	if e.Process.SHA256 != "" {
		file["hashes"] = []any{map[string]any{
			"algorithm_id": 3, "algorithm": "SHA-256", "value": e.Process.SHA256,
		}}
	}
	return file
}

func (e *Event) ocsfFile(doc map[string]any, class ocsfClass) {
	if class.classUID != ocsfClassFileActivity || e.File.Path == "" {
		return
	}
	file := map[string]any{"path": e.File.Path, "name": path.Base(e.File.Path), "type_id": 1, "type": "Regular File"}
	doc["file"] = file
	if e.File.Target != "" {
		doc["new_path"] = e.File.Target
	}
}

func (e *Event) ocsfNetwork(doc map[string]any, class ocsfClass) {
	if class.classUID != ocsfClassNetworkActivity && class.classUID != ocsfClassDNSActivity {
		return
	}
	if e.Network.SrcIP != "" {
		doc["src_endpoint"] = map[string]any{"ip": e.Network.SrcIP, "port": e.Network.SrcPort}
	}
	if e.Network.DstIP != "" {
		doc["dst_endpoint"] = map[string]any{"ip": e.Network.DstIP, "port": e.Network.DstPort}
	}
	if e.Network.Domain != "" {
		doc["query"] = map[string]any{"hostname": e.Network.Domain}
	}
}

func (e *Event) ocsfDevice(doc map[string]any) {
	if e.Host == "" {
		return
	}
	device := map[string]any{
		"hostname": e.Host,
		"type_id":  0,
		"os":       map[string]any{"name": "Linux", "type_id": 200, "type": "Linux"},
	}
	if e.Container.ID != "" {
		device["container"] = map[string]any{"uid": e.Container.ID, "runtime": e.Container.Runtime}
	}
	doc["device"] = device
}

// OCSF renders the alert as an OCSF Detection Finding (class 2004), the format
// an OCSF-aware SIEM ingests as a security finding.
func (a *Alert) OCSF() map[string]any {
	doc := map[string]any{
		"metadata":      ocsfMetadata(),
		"time":          a.Timestamp.UnixMilli(),
		"category_uid":  ocsfCatFindings,
		"category_name": "Findings",
		"class_uid":     ocsfClassDetectionFinding,
		"class_name":    "Detection Finding",
		"activity_id":   1,
		"activity_name": "Create",
		"type_uid":      ocsfClassDetectionFinding*100 + 1,
		"severity_id":   ocsfSeverityID(a.Severity),
		"severity":      ocsfSeverityName(a.Severity),
		"finding_info": map[string]any{
			"uid": a.RuleID, "title": a.RuleName, "desc": a.Description,
		},
	}
	if a.Technique.ID != "" {
		doc["attacks"] = []any{a.ocsfAttack()}
	}
	if a.RiskScore > 0 {
		doc["risk_score"] = a.RiskScore
	}
	if a.Event != nil {
		doc["evidences"] = []any{a.Event.OCSF()}
		doc["process"] = a.Event.ocsfProcess()
		a.Event.ocsfDevice(doc)
	}
	return doc
}

func (a *Alert) ocsfAttack() map[string]any {
	attack := map[string]any{
		"version":   "14.1",
		"technique": map[string]any{"uid": a.Technique.ID, "name": a.Technique.Name},
	}
	if a.Technique.Tactic != "" {
		attack["tactic"] = map[string]any{"name": a.Technique.Tactic}
	}
	return attack
}

func ocsfSeverityID(severity Severity) int {
	if id, ok := ocsfSeverityIDs[severity]; ok {
		return id
	}
	return 0
}

func ocsfSeverityName(severity Severity) string {
	if name, ok := ocsfSeverityNames[severity]; ok {
		return name
	}
	return "Unknown"
}
