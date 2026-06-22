// Package policy is the small posture document the control plane distributes to
// agents alongside the detection rules. It rides in the existing rule bundle as a
// reserved .yml file (the rule loader globs *.yaml, so it is ignored there) and
// the agent applies it through the responder — which clamps any pushed mode to
// the host's local max_mode ceiling, so a policy can never escalate enforcement
// past what the operator pinned.
package policy

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// FileName is the reserved bundle entry that carries the policy. The .yml suffix
// keeps it out of the agent's *.yaml rule glob.
const FileName = "argus-policy.yml"

// Response is the posture the fleet asks an agent to adopt.
type Response struct {
	Mode string `yaml:"mode"`
}

// Policy is the distributed document. It is intentionally minimal today (the
// response posture); new fields extend it without touching the wire contract.
type Policy struct {
	Response Response `yaml:"response"`
}

var validModes = map[string]bool{"off": true, "dry-run": true, "enforce": true}

// Parse decodes and validates a policy document, rejecting unknown keys and an
// invalid mode so a malformed policy fails at the source (server load) rather
// than silently doing nothing on every agent.
func Parse(data []byte) (Policy, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var parsed Policy
	if err := decoder.Decode(&parsed); err != nil {
		return Policy{}, fmt.Errorf("parse policy: %w", err)
	}
	if parsed.Response.Mode != "" && !validModes[parsed.Response.Mode] {
		return Policy{}, fmt.Errorf("policy response.mode %q invalid (want off|dry-run|enforce)", parsed.Response.Mode)
	}
	return parsed, nil
}

// Marshal renders a policy back to YAML bytes for distribution.
func (p Policy) Marshal() ([]byte, error) {
	data, err := yaml.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}
	return data, nil
}
