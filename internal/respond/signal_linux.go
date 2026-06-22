//go:build linux

package respond

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// signalGuarded re-reads /proc/<pid>/comm and refuses if it no longer matches
// what the alert observed — a cheap guard against signalling the wrong process
// after PID reuse — then delivers sig.
func signalGuarded(pid uint32, comm string, sig syscall.Signal) error {
	if comm != "" {
		actual, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			return fmt.Errorf("process %d gone: %w", pid, err)
		}
		if current := strings.TrimSpace(string(actual)); current != comm {
			return fmt.Errorf("pid %d is now %q, not %q: refusing to signal", pid, current, comm)
		}
	}
	return syscall.Kill(int(pid), sig)
}

func guardedKill(pid uint32, comm string) error   { return signalGuarded(pid, comm, syscall.SIGKILL) }
func guardedFreeze(pid uint32, comm string) error { return signalGuarded(pid, comm, syscall.SIGSTOP) }
