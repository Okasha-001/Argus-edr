//go:build !linux

package respond

import "errors"

// Process kill/freeze is POSIX-signal based and implemented for Linux only. On
// other platforms the rungs that would signal a process report this error instead
// (response enforcement is Linux-only today; observation and alerting are not).
var errSignalUnsupported = errors.New("process kill/freeze is only supported on linux")

func guardedKill(uint32, string) error   { return errSignalUnsupported }
func guardedFreeze(uint32, string) error { return errSignalUnsupported }
