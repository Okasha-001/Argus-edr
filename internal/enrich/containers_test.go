package enrich

import (
	"strings"
	"testing"
)

func TestParseContainerDocker(t *testing.T) {
	id := strings.Repeat("a1b2c3d4", 8) // 64 hex characters
	container := parseContainer("0::/system.slice/docker-" + id + ".scope")
	if container.ID != id {
		t.Errorf("id = %q, want %q", container.ID, id)
	}
	if container.Runtime != "docker" {
		t.Errorf("runtime = %q, want docker", container.Runtime)
	}
}

func TestParseContainerHostProcess(t *testing.T) {
	container := parseContainer("0::/init.scope")
	if container.ID != "" {
		t.Errorf("host process should have no container id, got %q", container.ID)
	}
}
