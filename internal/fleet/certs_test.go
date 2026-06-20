package fleet

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func devConfigs(t *testing.T) (server, client *tls.Config, ca []byte) {
	t.Helper()
	certs, err := GenerateDevCerts("argus-server")
	if err != nil {
		t.Fatalf("generate certs: %v", err)
	}
	server, err = ServerTLSConfig(certs.CA.Cert, certs.Server.Cert, certs.Server.Key)
	if err != nil {
		t.Fatalf("server config: %v", err)
	}
	client, err = ClientTLSConfig(certs.CA.Cert, certs.Agent.Cert, certs.Agent.Key, "argus-server")
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	return server, client, certs.CA.Cert
}

func TestMutualTLSHandshakeSucceeds(t *testing.T) {
	serverCfg, clientCfg, _ := devConfigs(t)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		serverErr <- conn.(*tls.Conn).Handshake()
	}()

	conn, err := tls.Dial("tcp", listener.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer conn.Close()
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 || peers[0].Subject.CommonName != "argus-server" {
		t.Errorf("unexpected server identity: %+v", peers)
	}
}

func TestServerRejectsClientWithoutCertificate(t *testing.T) {
	serverCfg, _, ca := devConfigs(t)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		if conn, err := listener.Accept(); err == nil {
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("could not load CA")
	}
	// Trusts the server but presents no client certificate.
	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		RootCAs:    pool,
		ServerName: "argus-server",
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		return // rejected at dial — acceptable
	}
	defer conn.Close()
	// With TLS 1.3 the rejection may surface on the first read instead.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the connection to be rejected without a client certificate")
	}
}
