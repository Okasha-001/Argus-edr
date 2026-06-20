package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/argus-edr/argus/internal/fleet"
)

// runGenCerts mints a development CA with a server certificate plus the shared
// agent certificate, and optionally a distinct per-host client certificate for
// each name in --agents. Production deployments should issue one certificate per
// host (via --agents or a managed CA), since the control plane binds each agent's
// identity to its certificate.
func runGenCerts(args []string) error {
	flags := flag.NewFlagSet("gen-certs", flag.ExitOnError)
	dir := flags.String("dir", "fleet-certs", "output directory for the generated certificates")
	dnsName := flags.String("dns", "argus-server", "server certificate DNS name; agents set fleet.server_name to this")
	agents := flags.String("agents", "", "comma-separated hostnames to mint a distinct per-agent client certificate for")
	if err := flags.Parse(args); err != nil {
		return err
	}

	certs, err := fleet.GenerateDevCerts(*dnsName)
	if err != nil {
		return fmt.Errorf("generate certs: %w", err)
	}
	if err := fleet.WriteDevCerts(*dir, certs); err != nil {
		return fmt.Errorf("write certs: %w", err)
	}

	fmt.Printf("wrote development certificates to %s/\n", *dir)
	fmt.Println("  ca.pem                       fleet CA (server and every agent need it)")
	fmt.Println("  server.pem, server-key.pem   control-plane certificate")
	fmt.Println("  agent.pem, agent-key.pem     shared agent certificate (demos only)")

	if err := writePerAgentCerts(*dir, *agents, certs); err != nil {
		return err
	}
	fmt.Printf("server DNS name is %q — set fleet.server_name to this on agents\n", *dnsName)
	return nil
}

// writePerAgentCerts mints one client certificate per requested hostname, each
// with a distinct key (so each is a distinct identity the server can pin).
func writePerAgentCerts(dir, agents string, certs *fleet.DevCerts) error {
	for _, name := range strings.Split(agents, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		pair, err := fleet.GenerateAgentCert(name, certs.CA.Cert, certs.CA.Key)
		if err != nil {
			return fmt.Errorf("mint cert for %q: %w", name, err)
		}
		certPath := filepath.Join(dir, name+".pem")
		keyPath := filepath.Join(dir, name+"-key.pem")
		if err := os.WriteFile(certPath, pair.Cert, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", certPath, err)
		}
		if err := os.WriteFile(keyPath, pair.Key, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", keyPath, err)
		}
		fmt.Printf("  %-28s per-agent certificate for %q\n", name+".pem, "+name+"-key.pem", name)
	}
	return nil
}
