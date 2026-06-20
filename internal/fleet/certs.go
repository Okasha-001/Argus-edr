// Package fleet holds the shared agent/control-plane transport: mTLS config,
// development certificate minting, and the agent-side client.
package fleet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const devCertValidity = 365 * 24 * time.Hour

// PEMPair is a PEM-encoded certificate and its private key.
type PEMPair struct {
	Cert []byte
	Key  []byte
}

// DevCerts is a self-signed CA plus a server and an agent leaf, enough to stand
// up mTLS for development, demos and tests. Production fleets should mint
// per-agent certificates from a managed CA.
type DevCerts struct {
	CA     PEMPair
	Server PEMPair
	Agent  PEMPair
}

// GenerateDevCerts creates a CA and signs a server certificate (valid for
// serverDNS plus 127.0.0.1) and an agent certificate under it.
func GenerateDevCerts(serverDNS string) (*DevCerts, error) {
	caCert, caKey, caPEM, err := generateCA()
	if err != nil {
		return nil, err
	}
	server, err := generateLeaf("argus-server", caCert, caKey,
		[]string{serverDNS}, []net.IP{net.IPv4(127, 0, 0, 1)}, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	agent, err := generateLeaf("argus-agent", caCert, caKey,
		nil, nil, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}
	return &DevCerts{
		CA:     PEMPair{Cert: caPEM, Key: encodeKey(caKey)},
		Server: server,
		Agent:  agent,
	}, nil
}

// GenerateAgentCert mints a client certificate with the given common name,
// signed by the provided CA (PEM cert + key). Production fleets call this to
// issue a distinct certificate per host, so the control plane can bind each
// agent's identity to its certificate and revoke hosts individually.
func GenerateAgentCert(commonName string, caCertPEM, caKeyPEM []byte) (PEMPair, error) {
	caCert, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return PEMPair{}, err
	}
	return generateLeaf(commonName, caCert, caKey, nil, nil, x509.ExtKeyUsageClientAuth)
}

func parseCA(caCertPEM, caKeyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certBlock, _ := pem.Decode(caCertPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("decode CA key PEM")
	}
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	return caCert, caKey, nil
}

// WriteDevCerts writes the certificates to dir: ca.pem, server.pem/server-key.pem,
// agent.pem/agent-key.pem. Keys are written 0600.
func WriteDevCerts(dir string, certs *DevCerts) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"ca.pem", certs.CA.Cert, 0o644},
		{"ca-key.pem", certs.CA.Key, 0o600},
		{"server.pem", certs.Server.Cert, 0o644},
		{"server-key.pem", certs.Server.Key, 0o600},
		{"agent.pem", certs.Agent.Cert, 0o644},
		{"agent-key.pem", certs.Agent.Key, 0o600},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ARGUS Dev CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(devCertValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, key, encodeCert(der), nil
}

func generateLeaf(commonName string, ca *x509.Certificate, caKey *ecdsa.PrivateKey,
	dnsNames []string, ips []net.IP, usage x509.ExtKeyUsage) (PEMPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return PEMPair{}, err
	}
	serial, err := newSerial()
	if err != nil {
		return PEMPair{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(devCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return PEMPair{}, err
	}
	return PEMPair{Cert: encodeCert(der), Key: encodeKey(key)}, nil
}

func newSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func encodeKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		// MarshalECPrivateKey only fails on an unsupported curve; P-256 is fine.
		panic(fmt.Sprintf("marshal ec key: %v", err))
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
