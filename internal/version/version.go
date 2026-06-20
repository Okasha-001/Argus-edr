// Package version exposes build metadata stamped in at link time.
package version

// Overridden via -ldflags "-X .../version.Version=... -X .../version.BuildDate=...".
var (
	Version   = "dev"
	BuildDate = "unknown"
)

// String returns a single human-readable version line.
func String() string {
	return "argus " + Version + " (built " + BuildDate + ")"
}
