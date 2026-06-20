package fleet

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// ServerTLSConfig builds a mutual-TLS config for the control plane: it presents
// the server certificate and requires every client to present a certificate
// signed by the fleet CA.
func ServerTLSConfig(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	pool, err := certPool(caPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLSConfig builds a mutual-TLS config for an agent: it presents the agent
// certificate and verifies the server against the fleet CA.
func ClientTLSConfig(caPEM, certPEM, keyPEM []byte, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	pool, err := certPool(caPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ServerTLSConfigFromFiles loads the CA, certificate and key from disk.
func ServerTLSConfigFromFiles(caFile, certFile, keyFile string) (*tls.Config, error) {
	ca, cert, key, err := readTriple(caFile, certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return ServerTLSConfig(ca, cert, key)
}

// ClientTLSConfigFromFiles loads the CA, certificate and key from disk.
func ClientTLSConfigFromFiles(caFile, certFile, keyFile, serverName string) (*tls.Config, error) {
	ca, cert, key, err := readTriple(caFile, certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return ClientTLSConfig(ca, cert, key, serverName)
}

func certPool(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("no valid certificate found in CA PEM")
	}
	return pool, nil
}

func readTriple(caFile, certFile, keyFile string) (ca, cert, key []byte, err error) {
	if ca, err = os.ReadFile(caFile); err != nil {
		return nil, nil, nil, fmt.Errorf("read CA: %w", err)
	}
	if cert, err = os.ReadFile(certFile); err != nil {
		return nil, nil, nil, fmt.Errorf("read cert: %w", err)
	}
	if key, err = os.ReadFile(keyFile); err != nil {
		return nil, nil, nil, fmt.Errorf("read key: %w", err)
	}
	return ca, cert, key, nil
}
