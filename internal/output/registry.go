package output

import (
	"fmt"
	"os"

	"github.com/argus-edr/argus/internal/config"
)

// Build constructs the configured sinks and groups them behind a MultiSink. If
// any sink fails to build, those already created are closed so nothing leaks.
func Build(specs []config.Output) (*MultiSink, error) {
	sinks := make([]Sink, 0, len(specs))
	for i, spec := range specs {
		sink, err := buildOne(spec)
		if err != nil {
			closeAll(sinks)
			return nil, fmt.Errorf("output[%d] (%s): %w", i, spec.Type, err)
		}
		sinks = append(sinks, sink)
	}
	return NewMultiSink(sinks...), nil
}

func buildOne(spec config.Output) (Sink, error) {
	switch spec.Type {
	case "stdout":
		return NewStdout(os.Stdout, spec.Format), nil
	case "file":
		return NewFile(spec.Path, spec.RotateMaxBytes)
	case "loki":
		return NewLoki(spec.Endpoint, spec.Labels), nil
	case "sqlite":
		return NewSQLite(spec.Path)
	default:
		return nil, fmt.Errorf("unknown output type %q", spec.Type)
	}
}

func closeAll(sinks []Sink) {
	for _, sink := range sinks {
		_ = sink.Close()
	}
}
