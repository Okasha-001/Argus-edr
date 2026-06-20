// Package output delivers events and alerts to one or more destinations behind
// a single Sink interface, so adding a backend never touches the pipeline.
package output

import (
	"errors"

	"github.com/argus-edr/argus/internal/model"
)

// Sink is a destination for events, alerts and correlated incidents.
type Sink interface {
	WriteEvent(event *model.Event) error
	WriteAlert(alert *model.Alert) error
	WriteIncident(incident *model.Incident) error
	Flush() error
	Close() error
}

// MultiSink fans writes out to several sinks. One sink failing does not stop the
// others; the combined error is returned.
type MultiSink struct {
	sinks []Sink
}

// NewMultiSink groups sinks behind one Sink.
func NewMultiSink(sinks ...Sink) *MultiSink {
	return &MultiSink{sinks: sinks}
}

func (m *MultiSink) WriteEvent(event *model.Event) error {
	var errs []error
	for _, sink := range m.sinks {
		if err := sink.WriteEvent(event); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *MultiSink) WriteAlert(alert *model.Alert) error {
	var errs []error
	for _, sink := range m.sinks {
		if err := sink.WriteAlert(alert); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *MultiSink) WriteIncident(incident *model.Incident) error {
	var errs []error
	for _, sink := range m.sinks {
		if err := sink.WriteIncident(incident); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *MultiSink) Flush() error {
	var errs []error
	for _, sink := range m.sinks {
		errs = append(errs, sink.Flush())
	}
	return errors.Join(errs...)
}

func (m *MultiSink) Close() error {
	var errs []error
	for _, sink := range m.sinks {
		errs = append(errs, sink.Close())
	}
	return errors.Join(errs...)
}
