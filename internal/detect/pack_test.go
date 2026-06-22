package detect

import (
	"crypto/ed25519"
	"testing"
)

func TestLoadPack(t *testing.T) {
	pack, err := LoadPack("../../rules/packs/community-linux")
	if err != nil {
		t.Fatalf("load pack: %v", err)
	}
	if pack.Manifest.Name != "community-linux" || pack.Manifest.Version == "" {
		t.Errorf("manifest = %+v", pack.Manifest)
	}
	if len(pack.Rules) < 2 {
		t.Errorf("expected the pack's rules to load, got %d", len(pack.Rules))
	}
	if pack.Digest == "" {
		t.Error("pack digest must be computed")
	}
}

func TestPackSignAndVerify(t *testing.T) {
	pack, err := LoadPack("../../rules/packs/community-linux")
	if err != nil {
		t.Fatalf("load pack: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signature := pack.Sign(priv)
	if err := pack.Verify(signature, pub); err != nil {
		t.Errorf("a freshly signed pack must verify: %v", err)
	}

	// A different key must not verify, and a tampered digest must fail.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := pack.Verify(signature, otherPub); err == nil {
		t.Error("verification with the wrong public key must fail")
	}
	pack.Digest = "deadbeef"
	if err := pack.Verify(signature, pub); err == nil {
		t.Error("verification must fail once the digest changes")
	}
}

func TestLoadPackRejectsMissingManifest(t *testing.T) {
	if _, err := LoadPack(t.TempDir()); err == nil {
		t.Fatal("a directory with no pack.yml must be rejected")
	}
}
