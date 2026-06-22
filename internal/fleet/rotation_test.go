package fleet

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertIssuerIssuesUsableClientCert(t *testing.T) {
	certs, err := GenerateDevCerts("argus-server")
	if err != nil {
		t.Fatalf("dev certs: %v", err)
	}
	issuer, err := NewCertIssuer(certs.CA.Cert, certs.CA.Key)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	pair, fingerprint, err := issuer.Issue("web-01")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if fingerprint == "" {
		t.Fatal("an issued certificate must report a fingerprint")
	}
	// The fingerprint the issuer reports is what the server stages as pending, so it
	// must equal CertFingerprint of the certificate it actually returned.
	got, err := CertFingerprint(pair.Cert)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if got != fingerprint {
		t.Errorf("issuer fingerprint %q != CertFingerprint %q", fingerprint, got)
	}
	// The minted keypair must be a usable mTLS client against the same CA.
	if _, err := ClientTLSConfig(certs.CA.Cert, pair.Cert, pair.Key, "argus-server"); err != nil {
		t.Errorf("issued cert is not a usable client keypair: %v", err)
	}
}

func TestCertIssuerRejectsMalformedCA(t *testing.T) {
	if _, err := NewCertIssuer([]byte("not a cert"), []byte("not a key")); err == nil {
		t.Fatal("expected NewCertIssuer to reject malformed CA material")
	}
}

func TestCertFingerprintMatchesServerComputation(t *testing.T) {
	// CertFingerprint(PEM) must equal sha256(DER), the exact value the server
	// derives from the live peer certificate (api.peerFingerprint). Recompute it
	// independently so the two code paths can never silently diverge.
	certs, err := GenerateDevCerts("argus-server")
	if err != nil {
		t.Fatalf("dev certs: %v", err)
	}
	fingerprint, err := CertFingerprint(certs.Agent.Cert)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	block, _ := pem.Decode(certs.Agent.Cert)
	sum := sha256.Sum256(block.Bytes)
	if want := hex.EncodeToString(sum[:]); fingerprint != want {
		t.Errorf("fingerprint = %q, want %q", fingerprint, want)
	}
}

func TestCertFingerprintRejectsNonPEM(t *testing.T) {
	if _, err := CertFingerprint([]byte("not pem")); err == nil {
		t.Fatal("expected CertFingerprint to reject non-PEM input")
	}
}

func TestKeypairLoaderReloadsRotatedCert(t *testing.T) {
	certs, err := GenerateDevCerts("argus-server")
	if err != nil {
		t.Fatalf("dev certs: %v", err)
	}
	issuer, err := NewCertIssuer(certs.CA.Cert, certs.CA.Key)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	rotated, _, err := issuer.Issue("web-01")
	if err != nil {
		t.Fatalf("issue rotated: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "agent.pem")
	keyPath := filepath.Join(dir, "agent-key.pem")
	writeFile(t, certPath, certs.Agent.Cert)
	writeFile(t, keyPath, certs.Agent.Key)

	loader := &keypairLoader{certFile: certPath, keyFile: keyPath}
	first, err := loader.load()
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if again, _ := loader.load(); !bytes.Equal(again.Certificate[0], first.Certificate[0]) {
		t.Fatal("an unchanged file must serve the cached certificate")
	}

	// Swap in the rotated keypair with a newer mod time: the loader must adopt it.
	writeFile(t, certPath, rotated.Cert)
	writeFile(t, keyPath, rotated.Key)
	future := time.Now().Add(time.Second)
	for _, path := range []string{certPath, keyPath} {
		if err := os.Chtimes(path, future, future); err != nil {
			t.Fatal(err)
		}
	}
	second, err := loader.load()
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Error("loader should have picked up the rotated certificate")
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
