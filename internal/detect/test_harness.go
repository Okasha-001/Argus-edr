package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/argus-edr/argus/internal/model"
	"gopkg.in/yaml.v3"
)

// Detection-as-code test harness. Every rule should ship with fixtures that prove
// it fires on the behaviour it targets and stays silent on benign look-alikes.
// `argus test-rules` (and `make test-rules`) runs these and reports the false-
// positive rate, so a rule change that starts crying wolf fails the build.

// Expectation values for a RuleTest.
const (
	ExpectFire   = "fire"
	ExpectNoFire = "no-fire"
)

// RuleTest is one assertion about a rule. Events use the same JSON shape as the
// replay fixtures (decoded into model.Event), so a test reads like the data the
// agent actually sees. Use Event for the common single-event case, or Events for
// a rule that needs context (the rule must fire on at least one of them).
type RuleTest struct {
	Name   string           `yaml:"name"`
	Rule   string           `yaml:"rule"`
	Expect string           `yaml:"expect"`
	Event  map[string]any   `yaml:"event"`
	Events []map[string]any `yaml:"events"`
}

func (t RuleTest) eventSpecs() []map[string]any {
	if t.Event != nil {
		return append([]map[string]any{t.Event}, t.Events...)
	}
	return t.Events
}

// LoadRuleTests reads every *.yaml in dir as a list of RuleTests and validates
// each, so a malformed test is reported at load rather than skipped silently.
func LoadRuleTests(dir string) ([]RuleTest, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("scan rule tests: %w", err)
	}
	var tests []RuleTest
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var fileTests []RuleTest
		if err := yaml.Unmarshal(raw, &fileTests); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		for i, test := range fileTests {
			if err := test.validate(); err != nil {
				return nil, fmt.Errorf("%s test %d: %w", path, i, err)
			}
			tests = append(tests, test)
		}
	}
	return tests, nil
}

func (t RuleTest) validate() error {
	if t.Rule == "" {
		return fmt.Errorf("missing rule id")
	}
	if t.Expect != ExpectFire && t.Expect != ExpectNoFire {
		return fmt.Errorf("expect must be %q or %q, got %q", ExpectFire, ExpectNoFire, t.Expect)
	}
	if len(t.eventSpecs()) == 0 {
		return fmt.Errorf("test %q has no event", t.Name)
	}
	return nil
}

// RuleTestResult is the outcome of one assertion.
type RuleTestResult struct {
	Name   string
	Rule   string
	Expect string
	Fired  bool
	Pass   bool
	Reason string // why it failed, for the report
}

// TestReport aggregates a run.
type TestReport struct {
	Results        []RuleTestResult
	Total          int
	Passed         int
	FalsePositives int // no-fire cases that fired (a rule crying wolf)
	FalseNegatives int // fire cases that did not fire (a rule gone blind)
	TestedRules    map[string]bool
}

// Failed returns the number of failing assertions.
func (r TestReport) Failed() int { return r.Total - r.Passed }

// FalsePositiveRate is the share of should-not-fire assertions that wrongly
// fired, the headline detection-quality number.
func (r TestReport) FalsePositiveRate() float64 {
	var noFire int
	for _, res := range r.Results {
		if res.Expect == ExpectNoFire {
			noFire++
		}
	}
	if noFire == 0 {
		return 0
	}
	return float64(r.FalsePositives) / float64(noFire)
}

// UntestedRules lists the ids of rules that no test exercised, so coverage gaps
// are visible rather than assumed away.
func (r TestReport) UntestedRules(rules []*Rule) []string {
	var missing []string
	for _, rule := range rules {
		if !r.TestedRules[rule.ID] {
			missing = append(missing, rule.ID)
		}
	}
	sort.Strings(missing)
	return missing
}

// RunRuleTests evaluates every test against the rules and returns the report. A
// test that names an unknown rule fails (rather than being ignored), so a typo or
// a deleted rule cannot leave a test quietly passing.
func RunRuleTests(rules []*Rule, tests []RuleTest) (TestReport, error) {
	byID := make(map[string]*Rule, len(rules))
	for _, rule := range rules {
		byID[rule.ID] = rule
	}
	report := TestReport{TestedRules: map[string]bool{}}
	for _, test := range tests {
		result, err := evaluateTest(byID, test)
		if err != nil {
			return TestReport{}, err
		}
		report.Total++
		if result.Pass {
			report.Passed++
		} else if test.Expect == ExpectNoFire {
			report.FalsePositives++
		} else {
			report.FalseNegatives++
		}
		report.TestedRules[test.Rule] = true
		report.Results = append(report.Results, result)
	}
	return report, nil
}

func evaluateTest(byID map[string]*Rule, test RuleTest) (RuleTestResult, error) {
	result := RuleTestResult{Name: test.Name, Rule: test.Rule, Expect: test.Expect}
	rule, ok := byID[test.Rule]
	if !ok {
		result.Reason = "unknown rule id"
		return result, nil
	}
	for _, spec := range test.eventSpecs() {
		event, err := specToEvent(spec)
		if err != nil {
			return RuleTestResult{}, fmt.Errorf("test %q: %w", test.Name, err)
		}
		if rule.Matches(event) {
			result.Fired = true
			break
		}
	}
	result.Pass = result.Fired == (test.Expect == ExpectFire)
	if !result.Pass {
		result.Reason = fmt.Sprintf("expected %s, rule %s", test.Expect, firedWord(result.Fired))
	}
	return result, nil
}

func firedWord(fired bool) string {
	if fired {
		return "fired"
	}
	return "did not fire"
}

// specToEvent turns a JSON-shaped event spec into a model.Event by round-tripping
// through JSON (the event's own wire format), then normalises it so Action maps
// to a Type exactly as a replayed event would.
func specToEvent(spec map[string]any) (*model.Event, error) {
	raw, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("encode event spec: %w", err)
	}
	var event model.Event
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, fmt.Errorf("decode event spec: %w", err)
	}
	event.Normalize()
	return &event, nil
}
