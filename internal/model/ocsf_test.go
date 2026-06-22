package model

import (
	"testing"
	"time"
)

func assertEqual(t *testing.T, field string, got, want any) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %#v, want %#v", field, got, want)
	}
}

func TestEventOCSFProcess(t *testing.T) {
	event := &Event{
		Timestamp: time.Unix(1700000000, 0).UTC(),
		Host:      "web-01",
		Action:    "exec",
		Type:      EventExec,
		Process: Process{
			PID: 1234, PPID: 1, Name: "bash",
			Executable: "/bin/bash", CommandLine: "bash -i", SHA256: "deadbeef",
		},
	}
	doc := event.OCSF()

	assertEqual(t, "class_uid", doc["class_uid"], ocsfClassProcessActivity)
	assertEqual(t, "category_uid", doc["category_uid"], ocsfCatSystem)
	assertEqual(t, "activity_id", doc["activity_id"], 1)
	assertEqual(t, "type_uid", doc["type_uid"], ocsfClassProcessActivity*100+1)

	meta, ok := doc["metadata"].(map[string]any)
	if !ok || meta["version"] != ocsfVersion {
		t.Fatalf("metadata = %#v", doc["metadata"])
	}
	process, ok := doc["process"].(map[string]any)
	if !ok {
		t.Fatalf("process missing: %#v", doc)
	}
	assertEqual(t, "process.pid", process["pid"], uint32(1234))
	device, ok := doc["device"].(map[string]any)
	if !ok {
		t.Fatalf("device missing: %#v", doc)
	}
	assertEqual(t, "device.hostname", device["hostname"], "web-01")
}

func TestEventOCSFNetwork(t *testing.T) {
	event := &Event{
		Timestamp: time.Now(),
		Action:    "connect",
		Type:      EventConnect,
		Network:   Network{SrcIP: "10.0.0.1", SrcPort: 5555, DstIP: "203.0.113.5", DstPort: 443},
	}
	doc := event.OCSF()

	assertEqual(t, "class_uid", doc["class_uid"], ocsfClassNetworkActivity)
	assertEqual(t, "category_uid", doc["category_uid"], ocsfCatNetwork)
	dst, ok := doc["dst_endpoint"].(map[string]any)
	if !ok {
		t.Fatalf("dst_endpoint missing: %#v", doc)
	}
	assertEqual(t, "dst_endpoint.ip", dst["ip"], "203.0.113.5")
	assertEqual(t, "dst_endpoint.port", dst["port"], uint16(443))
}

func TestAlertOCSFDetectionFinding(t *testing.T) {
	alert := &Alert{
		Timestamp: time.Now(),
		RuleID:    "R-0001",
		RuleName:  "Reverse shell",
		Severity:  SeverityCritical,
		Technique: Technique{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "execution"},
		RiskScore: 90,
		Event:     &Event{Action: "exec", Type: EventExec, Process: Process{PID: 5}},
	}
	doc := alert.OCSF()

	assertEqual(t, "class_uid", doc["class_uid"], ocsfClassDetectionFinding)
	assertEqual(t, "type_uid", doc["type_uid"], ocsfClassDetectionFinding*100+1)
	assertEqual(t, "severity_id", doc["severity_id"], 5)
	assertEqual(t, "severity", doc["severity"], "Critical")

	findingInfo, ok := doc["finding_info"].(map[string]any)
	if !ok {
		t.Fatalf("finding_info missing: %#v", doc)
	}
	assertEqual(t, "finding_info.uid", findingInfo["uid"], "R-0001")

	attacks, ok := doc["attacks"].([]any)
	if !ok || len(attacks) != 1 {
		t.Fatalf("attacks = %#v", doc["attacks"])
	}
	attack := attacks[0].(map[string]any)
	technique := attack["technique"].(map[string]any)
	assertEqual(t, "technique.uid", technique["uid"], "T1059")
}
