package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/argus-edr/argus/internal/sigma"
)

// runSigma converts upstream Sigma rules into a native ARGUS rule file. It reads
// the given files and directories, skips rules using features ARGUS cannot
// represent (with a note on stderr), and writes the rest as one YAML rule bundle.
func runSigma(args []string) error {
	flags := flag.NewFlagSet("sigma", flag.ExitOnError)
	outPath := flags.String("o", "", "output rule file (default: stdout)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() == 0 {
		return fmt.Errorf("argus sigma needs one or more sigma files or directories (usage: argus sigma [-o out.yaml] PATH)")
	}

	paths, err := gatherSigmaFiles(flags.Args())
	if err != nil {
		return err
	}

	rules, skipped := convertSigmaFiles(paths)
	if len(rules) == 0 {
		return fmt.Errorf("no rules converted (%d skipped)", skipped)
	}

	bundle, err := sigma.MarshalRules(rules)
	if err != nil {
		return fmt.Errorf("marshal rules: %w", err)
	}
	if err := writeSigmaBundle(*outPath, bundle); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "converted %d rules, skipped %d\n", len(rules), skipped)
	return nil
}

// convertSigmaFiles converts each file, skipping (with a stderr note) any that
// fail, and dropping duplicate ids so the bundle loads cleanly.
func convertSigmaFiles(paths []string) (rules []*sigma.Rule, skipped int) {
	seen := make(map[string]bool)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", path, err)
			skipped++
			continue
		}
		rule, err := sigma.Convert(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", filepath.Base(path), err)
			skipped++
			continue
		}
		if seen[rule.ID()] {
			fmt.Fprintf(os.Stderr, "skip %s: duplicate rule id %s\n", filepath.Base(path), rule.ID())
			skipped++
			continue
		}
		seen[rule.ID()] = true
		rules = append(rules, rule)
	}
	return rules, skipped
}

// gatherSigmaFiles expands directory arguments into the *.yml/*.yaml files they
// contain, recursively, and returns the full sorted list.
func gatherSigmaFiles(args []string) ([]string, error) {
	var paths []string
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", arg, err)
		}
		if !info.IsDir() {
			paths = append(paths, arg)
			continue
		}
		err = filepath.WalkDir(arg, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() && isSigmaFile(path) {
				paths = append(paths, path)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", arg, err)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func isSigmaFile(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	return extension == ".yml" || extension == ".yaml"
}

func writeSigmaBundle(outPath string, bundle []byte) error {
	if outPath == "" {
		_, err := os.Stdout.Write(bundle)
		return err
	}
	if err := os.WriteFile(outPath, bundle, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	return nil
}
