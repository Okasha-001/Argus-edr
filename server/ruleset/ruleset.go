// Package ruleset serves the fleet's canonical detection rules to agents. It
// loads a directory of YAML rule files, validates them with the same engine the
// agents run — so the control plane never distributes a ruleset that won't
// compile — and versions the bundle by a content hash. Agents compare that
// version on heartbeat and pull only when it changes.
package ruleset

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/argus-edr/argus/internal/detect"
	"github.com/argus-edr/argus/internal/model"
	"github.com/argus-edr/argus/internal/policy"
)

// versionLen is how many hex characters of the content hash name a version. A
// full SHA-256 is overkill for a human-facing tag; 12 hex chars (48 bits) make
// an accidental collision across a fleet's rule history negligible.
const versionLen = 12

// File is one rule file shipped to agents: its base name and raw YAML bytes.
type File struct {
	Name    string
	Content []byte
}

// Provider holds the current rule bundle and serves it concurrently. Reload
// swaps in a new bundle atomically, so an in-flight GetRules never sees a
// half-updated set.
type Provider struct {
	dir        string
	policyFile string // optional posture document distributed with the rules

	mu      sync.RWMutex
	version string
	files   []File
}

// NewProvider loads and validates the rules in dir, returning an error if any
// rule fails to compile so a misconfigured server refuses to start rather than
// shipping broken rules. policyFile, when non-empty, is a posture document
// (internal/policy) shipped to agents in the bundle; "" distributes rules only.
func NewProvider(dir, policyFile string) (*Provider, error) {
	provider := &Provider{dir: dir, policyFile: policyFile}
	if err := provider.Reload(); err != nil {
		return nil, err
	}
	return provider, nil
}

// Reload re-reads the rule directory and replaces the served bundle. The rules
// are validated before the swap, so a bad edit leaves the previous good bundle
// in place.
func (p *Provider) Reload() error {
	if _, err := detect.LoadDir(p.dir); err != nil {
		return fmt.Errorf("validate rules in %s: %w", p.dir, err)
	}

	paths, err := filepath.Glob(filepath.Join(p.dir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("scan rules dir: %w", err)
	}
	sort.Strings(paths)

	files := make([]File, 0, len(paths))
	hash := sha256.New()
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read rule file %s: %w", path, err)
		}
		name := filepath.Base(path)
		// Fold the name and length into the hash so renames and boundary shifts
		// change the version even if the concatenated bytes would not.
		fmt.Fprintf(hash, "%s\x00%d\x00", name, len(content))
		hash.Write(content)
		files = append(files, File{Name: name, Content: content})
	}
	policyFile, err := p.loadPolicy(hash)
	if err != nil {
		return err
	}
	if policyFile != nil {
		files = append(files, *policyFile)
	}
	version := hex.EncodeToString(hash.Sum(nil))[:versionLen]

	p.mu.Lock()
	p.version = version
	p.files = files
	p.mu.Unlock()
	return nil
}

// loadPolicy reads and validates the optional posture document, folds it into the
// version hash, and returns it as a bundle file. A missing path is rules-only
// distribution (not an error); a present-but-invalid policy fails the reload so
// the server never ships a posture agents would reject.
func (p *Provider) loadPolicy(digest hash.Hash) (*File, error) {
	if p.policyFile == "" {
		return nil, nil
	}
	content, err := os.ReadFile(p.policyFile)
	if err != nil {
		return nil, fmt.Errorf("read policy file %s: %w", p.policyFile, err)
	}
	if _, err := policy.Parse(content); err != nil {
		return nil, err
	}
	fmt.Fprintf(digest, "%s\x00%d\x00", policy.FileName, len(content))
	digest.Write(content)
	return &File{Name: policy.FileName, Content: content}, nil
}

// Version returns the current bundle's content version.
func (p *Provider) Version() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.version
}

// RuleInfo is one rule's metadata for the console's rule catalogue.
type RuleInfo struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Severity    string          `json:"severity"`
	Technique   model.Technique `json:"technique"`
	Enabled     bool            `json:"enabled"`
	RiskScore   int             `json:"risk_score"`
}

// Catalogue returns metadata for every rule in the served set. It recompiles the
// directory with the same loader agents use; admin reads are infrequent, so the
// re-read costs nothing meaningful and always reflects what was last reloaded.
func (p *Provider) Catalogue() ([]RuleInfo, error) {
	rules, err := detect.LoadDir(p.dir)
	if err != nil {
		return nil, fmt.Errorf("load rules for catalogue: %w", err)
	}
	infos := make([]RuleInfo, len(rules))
	for i, rule := range rules {
		infos[i] = RuleInfo{
			ID:          rule.ID,
			Name:        rule.Name,
			Description: rule.Description,
			Severity:    rule.Severity.String(),
			Technique:   rule.Technique,
			Enabled:     rule.Enabled,
			RiskScore:   rule.RiskScore,
		}
	}
	return infos, nil
}

// Bundle returns the current version and a copy of the file list. The slice is
// copied so a concurrent Reload cannot mutate a caller's view mid-iteration; the
// file contents themselves are immutable after load and are shared.
func (p *Provider) Bundle() (string, []File) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	files := make([]File, len(p.files))
	copy(files, p.files)
	return p.version, files
}
