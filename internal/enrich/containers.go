package enrich

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/argus-edr/argus/internal/model"
)

// A container id is a 64- or 32-char hex string embedded in the cgroup path.
var containerIDPattern = regexp.MustCompile(`[0-9a-f]{64}|[0-9a-f]{32}`)

var runtimeMarkers = []struct {
	marker  string
	runtime string
}{
	{"docker", "docker"},
	{"crio", "cri-o"},
	{"containerd", "containerd"},
	{"kubepods", "containerd"},
	{"libpod", "podman"},
}

// ContainerResolver derives container identity from a process's cgroup, caching
// per pid since cgroup membership does not change over a process's life.
type ContainerResolver struct {
	mu         sync.Mutex
	cache      map[uint32]model.Container
	readCgroup func(uint32) (string, error)
}

// NewContainerResolver returns a resolver that reads /proc/<pid>/cgroup.
func NewContainerResolver() *ContainerResolver {
	return &ContainerResolver{cache: make(map[uint32]model.Container), readCgroup: readProcCgroup}
}

// Resolve returns the container an event's process belongs to, or the zero
// Container for host processes.
func (r *ContainerResolver) Resolve(pid uint32) model.Container {
	r.mu.Lock()
	defer r.mu.Unlock()

	if c, ok := r.cache[pid]; ok {
		return c
	}
	content, err := r.readCgroup(pid)
	if err != nil {
		r.cache[pid] = model.Container{}
		return model.Container{}
	}
	container := parseContainer(content)
	r.cache[pid] = container
	return container
}

// parseContainer extracts the container id and runtime from cgroup file content.
func parseContainer(cgroup string) model.Container {
	id := containerIDPattern.FindString(cgroup)
	if id == "" {
		return model.Container{}
	}
	runtime := ""
	for _, m := range runtimeMarkers {
		if strings.Contains(cgroup, m.marker) {
			runtime = m.runtime
			break
		}
	}
	return model.Container{ID: id, Runtime: runtime}
}

func readProcCgroup(pid uint32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	return string(data), nil
}
