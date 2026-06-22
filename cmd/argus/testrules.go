package main

import (
	"flag"
	"fmt"

	"github.com/argus-edr/argus/internal/detect"
)

// runTestRules is the detection-as-code gate: it loads the rules and their
// should-fire / should-not-fire fixtures, runs every assertion, and fails the
// build on any wrong outcome or on a false-positive rate above the threshold.
func runTestRules(args []string) error {
	flags := flag.NewFlagSet("test-rules", flag.ExitOnError)
	rulesDir := flags.String("rules", "rules", "rules directory")
	testsDir := flags.String("tests", "rules/tests", "directory of rule-test fixtures")
	maxFPRate := flags.Float64("max-fp-rate", 0, "fail if the false-positive rate exceeds this (0 = no false positives allowed)")
	requireCoverage := flags.Bool("require-coverage", false, "fail if any rule has no test")
	if err := flags.Parse(args); err != nil {
		return err
	}

	rules, err := detect.LoadDir(*rulesDir)
	if err != nil {
		return err
	}
	tests, err := detect.LoadRuleTests(*testsDir)
	if err != nil {
		return err
	}
	if len(tests) == 0 {
		return fmt.Errorf("no rule tests found in %s", *testsDir)
	}
	report, err := detect.RunRuleTests(rules, tests)
	if err != nil {
		return err
	}

	printRuleTestReport(report, rules)
	return ruleTestExit(report, rules, *maxFPRate, *requireCoverage)
}

func printRuleTestReport(report detect.TestReport, rules []*detect.Rule) {
	for _, result := range report.Results {
		if !result.Pass {
			fmt.Printf("FAIL  %-8s %s — %s\n", result.Rule, result.Name, result.Reason)
		}
	}
	fmt.Printf("\nrule tests: %d/%d passed · %d false positive(s) · %d false negative(s) · FP rate %.1f%%\n",
		report.Passed, report.Total, report.FalsePositives, report.FalseNegatives, report.FalsePositiveRate()*100)
	tested := len(report.TestedRules)
	fmt.Printf("coverage: %d/%d rules have at least one test\n", tested, len(rules))
	if missing := report.UntestedRules(rules); len(missing) > 0 {
		fmt.Printf("untested: %v\n", missing)
	}
}

// ruleTestExit turns the report into a process error per the configured gates.
func ruleTestExit(report detect.TestReport, rules []*detect.Rule, maxFPRate float64, requireCoverage bool) error {
	if report.Failed() > 0 {
		return fmt.Errorf("%d rule test(s) failed", report.Failed())
	}
	if report.FalsePositiveRate() > maxFPRate {
		return fmt.Errorf("false-positive rate %.1f%% exceeds the %.1f%% threshold",
			report.FalsePositiveRate()*100, maxFPRate*100)
	}
	if requireCoverage {
		if missing := report.UntestedRules(rules); len(missing) > 0 {
			return fmt.Errorf("%d rule(s) have no test", len(missing))
		}
	}
	return nil
}
