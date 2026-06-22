package investigate

import (
	"testing"

	"github.com/argus-edr/argus/internal/model"
)

func event(action string, pid, ppid uint32, fn func(*model.Event)) *model.Event {
	e := &model.Event{Action: action, Host: "web-01"}
	e.Process = model.Process{PID: pid, PPID: ppid}
	if fn != nil {
		fn(e)
	}
	return e
}

func TestBuildReconstructsChain(t *testing.T) {
	events := []*model.Event{
		event("exec", 200, 100, func(e *model.Event) {
			e.Process.Name, e.Process.ParentName, e.Process.CommandLine = "bash", "nginx", "bash -i"
		}),
		event("open", 200, 100, func(e *model.Event) { e.Process.Name = "bash"; e.File.Path = "/etc/shadow" }),
		event("connect", 200, 100, func(e *model.Event) {
			e.Process.Name = "bash"
			e.Network = model.Network{DstIP: "203.0.113.9", DstPort: 4444}
		}),
	}
	annotations := []Annotation{
		{PID: 200, TechniqueID: "T1059", Severity: "high"},
		{PID: 200, TechniqueID: "T1003", Severity: "critical"},
	}

	graph := Build("web-01", events, annotations)

	proc := findNode(t, graph, "proc:200")
	if proc.Kind != KindProcess || proc.Label != "bash" || proc.Detail != "bash -i" {
		t.Errorf("process node = %+v", proc)
	}
	if !proc.Alerting || proc.Severity != "critical" {
		t.Errorf("process should be alerting at critical, got %+v", proc)
	}
	if len(proc.Techniques) != 2 || proc.Techniques[0] != "T1003" {
		t.Errorf("techniques = %v, want sorted [T1003 T1059]", proc.Techniques)
	}

	// nginx(100) --spawned--> bash(200) --opened--> /etc/shadow, --connected--> endpoint
	assertEdge(t, graph, "proc:100", "proc:200", "spawned")
	assertEdge(t, graph, "proc:200", "file:/etc/shadow", "opened")
	assertEdge(t, graph, "proc:200", "net:203.0.113.9:4444", "connected")

	if findNode(t, graph, "file:/etc/shadow").Label != "shadow" {
		t.Errorf("file label should be the basename")
	}
}

func TestBuildDedupsEdges(t *testing.T) {
	events := []*model.Event{
		event("connect", 5, 1, func(e *model.Event) { e.Network = model.Network{DstIP: "198.51.100.7", DstPort: 53} }),
		event("connect", 5, 1, func(e *model.Event) { e.Network = model.Network{DstIP: "198.51.100.7", DstPort: 53} }),
	}
	graph := Build("web-01", events, nil)
	count := 0
	for _, edge := range graph.Edges {
		if edge.Kind == "connected" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("repeated identical connections should collapse to one edge, got %d", count)
	}
}

func TestAnnotateUnknownPIDIsIgnored(t *testing.T) {
	events := []*model.Event{event("exec", 1, 0, func(e *model.Event) { e.Process.Name = "init" })}
	graph := Build("web-01", events, []Annotation{{PID: 999, TechniqueID: "T1000", Severity: "high"}})
	for _, node := range graph.Nodes {
		if node.Alerting {
			t.Errorf("an annotation for an absent pid must not mark any node alerting: %+v", node)
		}
	}
}

func findNode(t *testing.T, graph Graph, id string) Node {
	t.Helper()
	for _, node := range graph.Nodes {
		if node.ID == id {
			return node
		}
	}
	t.Fatalf("node %q not found in graph", id)
	return Node{}
}

func assertEdge(t *testing.T, graph Graph, source, target, kind string) {
	t.Helper()
	for _, edge := range graph.Edges {
		if edge.Source == source && edge.Target == target && edge.Kind == kind {
			return
		}
	}
	t.Fatalf("edge %s -%s-> %s not found", source, kind, target)
}
