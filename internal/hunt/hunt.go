// Package hunt is the ARQL threat-hunting engine: a small, readable query
// language over the event lake (internal/eventstore) that lets an analyst search
// for the unknown instead of waiting for a rule to fire. It reuses the same
// rule-visible fields the detection engine sees, so a hunt that proves useful
// can become a rule (Phase 16).
//
// Example queries:
//
//	exec where process.name in ("bash", "sh") and process.parent.name == "nginx"
//	connect where destination.port == 4444 | limit 50
//	sequence by host.name within 5m:
//	    exec where process.name == "curl";
//	    connect where destination.port == 4444
package hunt

import (
	"context"
	"time"

	"github.com/argus-edr/argus/internal/eventstore"
	"github.com/argus-edr/argus/internal/model"
)

// scanCap bounds how many events a single hunt pulls from the lake before
// filtering, so an open-ended query cannot exhaust memory. Scale-out backends
// push the predicates down instead of scanning (see docs/DATA_LAKE.md).
const scanCap = 50000

// Query is a compiled ARQL statement, ready to Run against a store.
type Query struct {
	source string
	simple *simpleQuery
	seq    *sequenceQuery
}

type classRef struct {
	action string
	all    bool
}

func (c classRef) matches(event *model.Event) bool {
	return c.all || event.Action == c.action
}

type pipe struct {
	filter   expr
	limit    int
	hasLimit bool
}

type simpleQuery struct {
	class  classRef
	filter expr
	pipes  []pipe
}

type stage struct {
	class  classRef
	filter expr
}

func (s stage) matches(event *model.Event) bool {
	return s.class.matches(event) && (s.filter == nil || s.filter.eval(event))
}

type sequenceQuery struct {
	by     string
	within time.Duration
	stages []stage
}

// Result holds either matched events (a simple query) or matched ordered chains
// (a sequence query).
type Result struct {
	Events    []*model.Event
	Sequences [][]*model.Event
}

// Count returns the number of matches, regardless of query shape.
func (r Result) Count() int {
	if r.Sequences != nil {
		return len(r.Sequences)
	}
	return len(r.Events)
}

// Compile parses ARQL source into an executable Query, validating fields,
// operators and regular expressions up front.
func Compile(source string) (*Query, error) {
	return parse(source)
}

// Classes returns the event-class verbs a query can open with, plus the two
// wildcards (`any`, `event`) that match every class. The console offers them for
// autocompletion alongside the field list.
func Classes() []string {
	return append([]string{"any", "event"}, model.KnownActions()...)
}

// Source returns the original query text.
func (q *Query) Source() string { return q.source }

// Run executes the query against the event lake.
func (q *Query) Run(ctx context.Context, store eventstore.Store) (Result, error) {
	if q.seq != nil {
		return q.runSequence(ctx, store)
	}
	return q.runSimple(ctx, store)
}

func (q *Query) runSimple(ctx context.Context, store eventstore.Store) (Result, error) {
	storeQuery := eventstore.Query{Limit: scanCap}
	if !q.simple.class.all {
		storeQuery.Action = q.simple.class.action
	}
	events, err := store.Query(ctx, storeQuery)
	if err != nil {
		return Result{}, err
	}
	events = filterEvents(events, q.simple.filter)
	limit := 0
	for _, p := range q.simple.pipes {
		if p.filter != nil {
			events = filterEvents(events, p.filter)
		}
		if p.hasLimit {
			limit = p.limit
		}
	}
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return Result{Events: events}, nil
}

func filterEvents(events []*model.Event, filter expr) []*model.Event {
	if filter == nil {
		return events
	}
	kept := make([]*model.Event, 0, len(events))
	for _, event := range events {
		if filter.eval(event) {
			kept = append(kept, event)
		}
	}
	return kept
}

func (q *Query) runSequence(ctx context.Context, store eventstore.Store) (Result, error) {
	events, err := store.Query(ctx, eventstore.Query{Limit: scanCap, Ascending: true})
	if err != nil {
		return Result{}, err
	}
	groups := q.groupBy(events)
	var sequences [][]*model.Event
	for _, group := range groups {
		sequences = append(sequences, matchSequences(group, q.seq)...)
	}
	return Result{Sequences: sequences}, nil
}

// groupBy partitions events by the sequence's `by` field so a chain is only
// matched within a single host/process/etc. With no `by`, all events form one
// group keyed by "".
func (q *Query) groupBy(events []*model.Event) map[string][]*model.Event {
	groups := make(map[string][]*model.Event)
	for _, event := range events {
		key := ""
		if q.seq.by != "" {
			raw, ok := event.Field(q.seq.by)
			if !ok {
				continue
			}
			key = toString(raw)
		}
		groups[key] = append(groups[key], event)
	}
	return groups
}

// partial is an in-progress sequence match: the events captured so far and the
// next stage index it is waiting on.
type partial struct {
	events []*model.Event
	stage  int
	start  time.Time
}

// matchSequences scans one time-ordered group and returns every ordered chain
// that satisfies the stages in order within the time window. Stage 0 opens a new
// partial; a later event that matches the next stage (and is inside the window)
// advances it; reaching the last stage completes a chain.
func matchSequences(group []*model.Event, seq *sequenceQuery) [][]*model.Event {
	var open []partial
	var done [][]*model.Event
	for _, event := range group {
		open = advancePartials(open, event, seq, &done)
		if seq.stages[0].matches(event) {
			open = append(open, partial{events: []*model.Event{event}, stage: 1, start: event.Timestamp})
		}
	}
	return done
}

func advancePartials(open []partial, event *model.Event, seq *sequenceQuery, done *[][]*model.Event) []partial {
	next := open[:0]
	for _, p := range open {
		if seq.within > 0 && event.Timestamp.Sub(p.start) > seq.within {
			continue // window expired: drop the partial
		}
		if !seq.stages[p.stage].matches(event) {
			next = append(next, p) // still open, keep waiting
			continue
		}
		advanced := partial{
			events: append(append([]*model.Event{}, p.events...), event),
			stage:  p.stage + 1,
			start:  p.start,
		}
		if advanced.stage == len(seq.stages) {
			*done = append(*done, advanced.events)
		} else {
			next = append(next, advanced)
		}
	}
	return next
}
