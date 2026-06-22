package detect

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Rule packs make detections shareable, versioned content. A pack is a directory
// with a `pack.yml` manifest and one or more `*.yaml` rule files (the .yml
// manifest is skipped by the .yaml rule glob, so the same directory loads as
// rules). LoadPack computes a content digest over the manifest and every rule
// file; the digest can be signed (ed25519) and verified, so a consumer knows a
// pack arrived unaltered from its author.
const packManifestName = "pack.yml"

// PackManifest describes a pack's identity.
type PackManifest struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description,omitempty"`
	Author      string `yaml:"author,omitempty"`
}

// Pack is a loaded, validated rule pack.
type Pack struct {
	Manifest PackManifest
	Rules    []*Rule
	// Digest is the hex SHA-256 over the manifest bytes and every rule file's
	// bytes, in sorted path order — the value a signature covers.
	Digest string
}

// LoadPack reads and validates a pack directory: the manifest, its rules, and the
// content digest. A pack whose rules do not compile is rejected here, not at use.
func LoadPack(dir string) (*Pack, error) {
	manifestBytes, err := os.ReadFile(filepath.Join(dir, packManifestName))
	if err != nil {
		return nil, fmt.Errorf("read pack manifest: %w", err)
	}
	var manifest PackManifest
	if err := yaml.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("parse pack manifest: %w", err)
	}
	if manifest.Name == "" || manifest.Version == "" {
		return nil, fmt.Errorf("pack manifest needs a name and a version")
	}
	rules, err := LoadDir(dir) // globs *.yaml; pack.yml is skipped by the extension
	if err != nil {
		return nil, fmt.Errorf("load pack rules: %w", err)
	}
	digest, err := packDigest(dir, manifestBytes)
	if err != nil {
		return nil, err
	}
	return &Pack{Manifest: manifest, Rules: rules, Digest: digest}, nil
}

// packDigest hashes the manifest followed by each rule file's bytes in sorted
// path order, so the digest is stable regardless of filesystem iteration order
// and changes if any rule or the manifest changes.
func packDigest(dir string, manifestBytes []byte) (string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return "", fmt.Errorf("scan pack: %w", err)
	}
	sort.Strings(paths)
	hash := sha256.New()
	hash.Write(manifestBytes)
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		hash.Write([]byte(filepath.Base(path)))
		hash.Write(content)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Sign returns a base64 ed25519 signature over the pack's digest. The private key
// stays with the author and is never committed.
func (p *Pack) Sign(key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(p.Digest)))
}

// Verify checks a base64 ed25519 signature against the pack's digest and the
// author's public key, so a tampered pack (rules changed after signing) fails.
func (p *Pack) Verify(signature string, key ed25519.PublicKey) error {
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(key, []byte(p.Digest), raw) {
		return fmt.Errorf("pack signature does not match digest (tampered or wrong key)")
	}
	return nil
}
