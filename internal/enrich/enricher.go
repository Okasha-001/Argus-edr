package enrich

import (
	"fmt"
	"os"
	"strings"

	"github.com/argus-edr/argus/internal/model"
	"github.com/argus-edr/argus/internal/yara"
)

// Options selects which enrichers are active, mirroring the config block.
type Options struct {
	ProcessTree     bool
	ResolveUsers    bool
	ContainerAware  bool
	HashExecutables bool
	HashMaxBytes    int64
	Yara            *yara.Engine // nil disables YARA scanning
	YaraMaxBytes    int64
}

// Enricher annotates events in place as they pass through the pipeline. In-place
// mutation is deliberate: enrichment augments the single event the pipeline owns
// rather than allocating a copy per event on the hot path.
type Enricher struct {
	tree       *ProcessTree
	users      *UserResolver
	containers *ContainerResolver
	hasher     *Hasher
	yara       *YaraScanner
}

// New builds an enricher with only the components enabled in opts.
func New(opts Options) *Enricher {
	e := &Enricher{}
	if opts.ProcessTree {
		e.tree = NewProcessTree()
	}
	if opts.ResolveUsers {
		e.users = NewUserResolver()
	}
	if opts.ContainerAware {
		e.containers = NewContainerResolver()
	}
	if opts.HashExecutables {
		e.hasher = NewHasher(opts.HashMaxBytes)
	}
	if opts.Yara != nil {
		e.yara = NewYaraScanner(opts.Yara, opts.YaraMaxBytes)
	}
	return e
}

// Enrich adds context to a single event.
func (e *Enricher) Enrich(event *model.Event) {
	if e.tree != nil {
		e.tree.Enrich(event)
	}
	if e.users != nil && event.User.Name == "" {
		event.User.Name = e.users.Name(event.User.ID)
	}
	if e.containers != nil && event.Container.ID == "" {
		event.Container = e.containers.Resolve(event.Process.PID)
	}
	if e.hasher != nil {
		e.hashExecutable(event)
	}
	if e.yara != nil {
		e.scanExecutable(event)
	}
	e.markStdioSocket(event)
}

func (e *Enricher) scanExecutable(event *model.Event) {
	isExec := event.Type == model.EventExec || event.Type == model.EventExecBlocked
	if isExec && event.Process.Executable != "" && len(event.Process.YaraMatches) == 0 {
		event.Process.YaraMatches = e.yara.Scan(event.Process.Executable)
	}
}

func (e *Enricher) hashExecutable(event *model.Event) {
	isExec := event.Type == model.EventExec || event.Type == model.EventExecBlocked
	if isExec && event.Process.Executable != "" && event.Process.SHA256 == "" {
		event.Process.SHA256 = e.hasher.Hash(event.Process.Executable)
	}
}

// markStdioSocket flags a shell whose stdio is a socket — the signature of a
// reverse shell. It never clears a flag already set (e.g. by replayed events).
func (e *Enricher) markStdioSocket(event *model.Event) {
	if event.Type != model.EventExec || event.Process.StdioSocket || !isShell(event.Process.Name) {
		return
	}
	event.Process.StdioSocket = stdioIsSocket(event.Process.PID)
}

var shellNames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true,
}

func isShell(name string) bool {
	return shellNames[name]
}

func stdioIsSocket(pid uint32) bool {
	for _, fd := range []int{0, 1, 2} {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
		if err == nil && strings.HasPrefix(target, "socket:") {
			return true
		}
	}
	return false
}
