// Package investigate reconstructs the story of an attack as a graph the analyst
// can read at a glance. From a host's events it builds nodes (processes, files,
// network endpoints) and the causal edges between them (a process spawned a
// child, opened a file, connected out), then annotates the nodes that fired
// detections with their ATT&CK techniques. It is a pure transform over events —
// no I/O, fully testable — so the control plane wires it to the event lake and
// the alert store without this package depending on either.
package investigate

import (
	"sort"
	"strconv"
	"strings"

	"github.com/argus-edr/argus/internal/model"
)

// Node kinds. The console colours and lays out nodes by kind.
const (
	KindProcess = "process"
	KindFile    = "file"
	KindNetwork = "network"
)

// Node is one entity in the attack graph.
type Node struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Label      string   `json:"label"`
	PID        uint32   `json:"pid,omitempty"`
	Detail     string   `json:"detail,omitempty"`     // command line / file path / endpoint
	Techniques []string `json:"techniques,omitempty"` // ATT&CK ids of detections on this node
	Severity   string   `json:"severity,omitempty"`   // highest alert severity touching it
	Alerting   bool     `json:"alerting,omitempty"`
}

// Edge is a directed causal relationship between two nodes.
type Edge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"` // spawned | opened | deleted | renamed | chmod | connected | resolved
}

// Graph is the reconstructed attack, ready to serialise to the console.
type Graph struct {
	Host  string `json:"host"`
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// Annotation links a fired detection to the process it fired on, so the graph
// carries ATT&CK context. The caller builds these from the alert store; keeping
// it a plain struct is what lets investigate stay independent of server/store.
type Annotation struct {
	PID         uint32
	TechniqueID string
	Severity    string
}

// fileEdgeKinds maps a file-touching event action to the edge label that reads
// best in the graph. Other actions fall back to "accessed".
var fileEdgeKinds = map[string]string{
	"open":   "opened",
	"unlink": "deleted",
	"rename": "renamed",
	"chmod":  "chmod",
}

type builder struct {
	nodes map[string]*Node
	edges map[string]Edge // keyed by source|target|kind for dedup
	order []string        // node ids in first-seen order, before the final sort
}

// Build reconstructs the attack graph for one host from its events and the
// detection annotations that touch them. Events should already be scoped to the
// host and time window of interest (the lake query does that); Build does not
// fetch anything.
func Build(host string, events []*model.Event, annotations []Annotation) Graph {
	b := &builder{nodes: map[string]*Node{}, edges: map[string]Edge{}}
	for _, event := range events {
		b.addEvent(event)
	}
	for _, ann := range annotations {
		b.annotate(ann)
	}
	return b.finish(host)
}

func (b *builder) addEvent(event *model.Event) {
	actor := b.process(event.Process.PID, event.Process.Name, event.Process.Executable, event.Process.CommandLine)
	b.linkParent(event, actor)
	switch {
	case event.File.Path != "":
		b.link(actor, b.file(event.File.Path), edgeKind(event.Action, fileEdgeKinds, "accessed"))
	case event.Action == "dns" && event.Network.Domain != "":
		b.link(actor, b.network(event.Network.Domain), "resolved")
	case event.Network.DstIP != "":
		b.link(actor, b.network(endpoint(event.Network.DstIP, event.Network.DstPort)), "connected")
	}
}

// linkParent adds the parent process and the spawn edge for an exec/fork. The
// parent is created from the child's ParentName so the tree is connected even
// when the parent's own exec predates the window.
func (b *builder) linkParent(event *model.Event, child *Node) {
	if event.Process.PPID == 0 || (event.Action != "exec" && event.Action != "fork") {
		return
	}
	parent := b.process(event.Process.PPID, event.Process.ParentName, event.Process.ParentExecutable, "")
	b.link(parent, child, "spawned")
}

func (b *builder) process(pid uint32, name, executable, commandLine string) *Node {
	id := "proc:" + strconv.FormatUint(uint64(pid), 10)
	node := b.ensure(id, KindProcess, processLabel(name, executable, pid))
	node.PID = pid
	if node.Label == "" || node.Label == "pid "+strconv.FormatUint(uint64(pid), 10) {
		node.Label = processLabel(name, executable, pid)
	}
	if commandLine != "" {
		node.Detail = commandLine
	}
	return node
}

func (b *builder) file(path string) *Node {
	node := b.ensure("file:"+path, KindFile, baseName(path))
	node.Detail = path
	return node
}

func (b *builder) network(endpoint string) *Node {
	node := b.ensure("net:"+endpoint, KindNetwork, endpoint)
	node.Detail = endpoint
	return node
}

func (b *builder) ensure(id, kind, label string) *Node {
	if node, ok := b.nodes[id]; ok {
		return node
	}
	node := &Node{ID: id, Kind: kind, Label: label}
	b.nodes[id] = node
	b.order = append(b.order, id)
	return node
}

func (b *builder) link(source, target *Node, kind string) {
	key := source.ID + "|" + target.ID + "|" + kind
	if _, ok := b.edges[key]; !ok {
		b.edges[key] = Edge{Source: source.ID, Target: target.ID, Kind: kind}
	}
}

func (b *builder) annotate(ann Annotation) {
	node, ok := b.nodes["proc:"+strconv.FormatUint(uint64(ann.PID), 10)]
	if !ok {
		return // an alert on a process with no events in the window: nothing to attach
	}
	node.Alerting = true
	if ann.TechniqueID != "" && !contains(node.Techniques, ann.TechniqueID) {
		node.Techniques = append(node.Techniques, ann.TechniqueID)
		sort.Strings(node.Techniques)
	}
	if severityRank(ann.Severity) > severityRank(node.Severity) {
		node.Severity = ann.Severity
	}
}

// finish produces a deterministically ordered graph so the API output and the
// tests are stable regardless of event/map iteration order.
func (b *builder) finish(host string) Graph {
	graph := Graph{Host: host, Nodes: make([]Node, 0, len(b.nodes)), Edges: make([]Edge, 0, len(b.edges))}
	for _, id := range b.order {
		graph.Nodes = append(graph.Nodes, *b.nodes[id])
	}
	sort.Slice(graph.Nodes, func(i, j int) bool { return graph.Nodes[i].ID < graph.Nodes[j].ID })
	for _, edge := range b.edges {
		graph.Edges = append(graph.Edges, edge)
	}
	sort.Slice(graph.Edges, func(i, j int) bool {
		if graph.Edges[i].Source != graph.Edges[j].Source {
			return graph.Edges[i].Source < graph.Edges[j].Source
		}
		if graph.Edges[i].Target != graph.Edges[j].Target {
			return graph.Edges[i].Target < graph.Edges[j].Target
		}
		return graph.Edges[i].Kind < graph.Edges[j].Kind
	})
	return graph
}

func edgeKind(action string, table map[string]string, fallback string) string {
	if kind, ok := table[action]; ok {
		return kind
	}
	return fallback
}

func processLabel(name, executable string, pid uint32) string {
	if name != "" {
		return name
	}
	if executable != "" {
		return baseName(executable)
	}
	return "pid " + strconv.FormatUint(uint64(pid), 10)
}

func baseName(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 && i < len(path)-1 {
		return path[i+1:]
	}
	return path
}

func endpoint(ip string, port uint16) string {
	if port == 0 {
		return ip
	}
	return ip + ":" + strconv.FormatUint(uint64(port), 10)
}

var severityOrder = map[string]int{"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

func severityRank(severity string) int { return severityOrder[strings.ToLower(severity)] }

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
