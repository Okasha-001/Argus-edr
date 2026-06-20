package main

import (
	"flag"
	"fmt"

	"github.com/argus-edr/argus/internal/detect"
)

func runRules(args []string) error {
	flags := flag.NewFlagSet("rules", flag.ExitOnError)
	rulesDir := flags.String("dir", "rules", "rules directory")
	if err := flags.Parse(args); err != nil {
		return err
	}

	rules, err := detect.LoadDir(*rulesDir)
	if err != nil {
		return err
	}

	fmt.Printf("loaded %d rules from %s\n\n", len(rules), *rulesDir)
	fmt.Printf("%-8s  %-8s  %-10s  %s\n", "ID", "SEVERITY", "TECHNIQUE", "NAME")
	for _, rule := range rules {
		fmt.Printf("%-8s  %-8s  %-10s  %s\n", rule.ID, rule.Severity, rule.Technique.ID, rule.Name)
	}
	return nil
}
