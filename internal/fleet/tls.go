package fleet

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
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

// ClientTLSConfigReloadingFromFiles is ClientTLSConfigFromFiles that reloads the
// client keypair from disk on every handshake, so an agent picks up a rotated
// certificate on its next reconnect without a code change or a config reload. The
// CA pool and server name are fixed at construction; only the client cert is
// dynamic. It fails fast if the certificate is missing or invalid at dial time.
func ClientTLSConfigReloadingFromFiles(caFile, certFile, keyFile, serverName string) (*tls.Config, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool, err := certPool(ca)
	if err != nil {
		return nil, err
	}
	loader := &keypairLoader{certFile: certFile, keyFile: keyFile}
	if _, err := loader.load(); err != nil {
		return nil, err
	}
	return &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return loader.load() },
		RootCAs:              pool,
		ServerName:           serverName,
		MinVersion:           tls.VersionTLS13,
	}, nil
}

// keypairLoader caches a parsed client keypair and reloads it only when either
// file's modification time advances, so the common no-rotation handshake stays a
// cache hit while a swapped certificate is adopted on the next connection.
type keypairLoader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cached  *tls.Certificate
	modTime time.Time
}

func (l *keypairLoader) load() (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	newest, err := newestModTime(l.certFile, l.keyFile)
	if err != nil {
		return nil, err
	}
	if l.cached != nil && newest.Equal(l.modTime) {
		return l.cached, nil
	}
	certPEM, err := os.ReadFile(l.certFile)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(l.keyFile)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	l.cached = &cert
	l.modTime = newest
	return l.cached, nil
}

func newestModTime(paths ...string) (time.Time, error) {
	var newest time.Time
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return time.Time{}, fmt.Errorf("stat %s: %w", path, err)
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest, nil
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
