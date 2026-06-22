package config

import "testing"

// withOutputs returns the defaults with their single stdout sink replaced by the
// given outputs, so a test exercises only output validation.
func withOutputs(outputs ...Output) Config {
	cfg := Defaults()
	cfg.Agent.Hostname = "web-01"
	cfg.Response.MaxMode = cfg.Response.Mode // Load() fills this; validate() requires it
	cfg.Outputs = outputs
	return cfg
}

func TestEventStoreOutputValidation(t *testing.T) {
	tests := []struct {
		name    string
		output  Output
		wantErr bool
	}{
		{"memory default", Output{Type: "eventstore"}, false},
		{"memory explicit", Output{Type: "eventstore", Format: "memory"}, false},
		{"sqlite with path", Output{Type: "eventstore", Format: "sqlite", Path: "/var/lib/argus/lake.db"}, false},
		{"sqlite without path", Output{Type: "eventstore", Format: "sqlite"}, true},
		{"bad backend", Output{Type: "eventstore", Format: "redis"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := withOutputs(tc.output).validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}
