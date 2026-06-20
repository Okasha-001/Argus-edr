package main

import (
	"flag"
	"fmt"

	"github.com/argus-edr/argus/internal/fleet"
)

// runGenCerts mints a development CA with a server and an agent certificate. It
// is a convenience for demos and local fleets; production deployments should
// issue per-agent certificates from a managed CA.
func runGenCerts(args []string) error {
	flags := flag.NewFlagSet("gen-certs", flag.ExitOnError)
	dir := flags.String("dir", "fleet-certs", "output directory for the generated certificates")
	dnsName := flags.String("dns", "argus-server", "server certificate DNS name; agents set fleet.server_name to this")
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
	fmt.Println("  agent.pem, agent-key.pem     agent certificate")
	fmt.Printf("server DNS name is %q — set fleet.server_name to this on agents\n", *dnsName)
	return nil
}
