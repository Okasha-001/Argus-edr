package detect

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/argus-edr/argus/internal/model"
	"gopkg.in/yaml.v3"
)

type ruleYAML struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
	Technique   struct {
		ID     string `yaml:"id"`
		Name   string `yaml:"name"`
		Tactic string `yaml:"tactic"`
	} `yaml:"technique"`
	Enabled   *bool      `yaml:"enabled"`
	RiskScore int        `yaml:"risk_score"`
	Response  string     `yaml:"response"`
	Match     *Condition `yaml:"match"`
}

// LoadDir reads every *.yaml rule file directly under dir and returns the
// compiled rules sorted by ID. Duplicate IDs and malformed rules are errors.
func LoadDir(dir string) ([]*Rule, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("scan rules dir: %w", err)
	}

	var rules []*Rule
	seen := make(map[string]string)
	for _, path := range paths {
		fileRules, err := loadFile(path)
		if err != nil {
			return nil, err
		}
		for _, rule := range fileRules {
			if other, dup := seen[rule.ID]; dup {
				return nil, fmt.Errorf("duplicate rule id %s in %s and %s", rule.ID, other, path)
			}
			seen[rule.ID] = path
			rules = append(rules, rule)
		}
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules found in %s", dir)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules, nil
}

func loadFile(path string) ([]*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rule file: %w", err)
	}

	var docs []ruleYAML
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&docs); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	rules := make([]*Rule, 0, len(docs))
	for _, doc := range docs {
		rule, err := compileRule(doc)
		if err != nil {
			return nil, fmt.Errorf("%s: rule %s: %w", filepath.Base(path), doc.ID, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func compileRule(doc ruleYAML) (*Rule, error) {
	if doc.ID == "" {
		return nil, fmt.Errorf("missing id")
	}
	if doc.Match == nil {
		return nil, fmt.Errorf("missing match block")
	}
	severity, err := model.ParseSeverity(doc.Severity)
	if err != nil {
		return nil, err
	}
	if err := doc.Match.Compile(); err != nil {
		return nil, err
	}

	enabled := true
	if doc.Enabled != nil {
		enabled = *doc.Enabled
	}
	return &Rule{
		ID:          doc.ID,
		Name:        doc.Name,
		Description: doc.Description,
		Severity:    severity,
		Technique:   model.Technique(doc.Technique),
		Enabled:     enabled,
		RiskScore:   doc.RiskScore,
		Response:    doc.Response,
		Match:       doc.Match,
	}, nil
}
