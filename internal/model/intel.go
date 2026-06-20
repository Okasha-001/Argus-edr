package model

// IntelHit is one threat-intelligence indicator that matched an event: the
// matched value, its type (ip|domain|hash), the event field it matched on, and
// the feed it came from. The detection engine turns each hit into an alert.
type IntelHit struct {
	Indicator string
	Type      string
	Field     string
	Source    string
}
