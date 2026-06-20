// Command argus-server is the ARGUS control plane for fleet management. It runs
// the FleetService over gRPC/mTLS — agent enrollment, heartbeats, alert
// ingestion and rule distribution — alongside a small JSON admin API for fleet
// visibility and pushing commands. See docs/FLEET.md.
package main

import (
	"fmt"
	"os"

	"github.com/argus-edr/argus/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if err := dispatch(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "argus-server:", err)
		os.Exit(1)
	}
}

func dispatch(command string, args []string) error {
	switch command {
	case "serve":
		return runServe(args)
	case "gen-certs":
		return runGenCerts(args)
	case "version":
		fmt.Println(version.String())
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `ARGUS control plane — fleet management over gRPC/mTLS

usage: argus-server <command> [flags]

commands:
  serve      run the control plane (gRPC FleetService + admin HTTP API)
  gen-certs  mint a development CA with server and agent certificates
  version    print the version

run "argus-server <command> -h" for a command's flags
`)
}
