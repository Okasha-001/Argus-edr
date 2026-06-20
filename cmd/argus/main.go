// Command argus is the ARGUS eBPF endpoint detection & response agent.
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
		fmt.Fprintln(os.Stderr, "argus:", err)
		os.Exit(1)
	}
}

func dispatch(command string, args []string) error {
	switch command {
	case "run":
		return runAgent(args)
	case "replay":
		return runReplay(args)
	case "rules":
		return runRules(args)
	case "sigma":
		return runSigma(args)
	case "baseline":
		return runBaseline(args)
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
	fmt.Fprint(os.Stderr, `ARGUS — eBPF endpoint detection & response

usage: argus <command> [flags]

commands:
  run      run the agent against the configured source (live eBPF by default)
  replay   run the pipeline over a recorded NDJSON event stream (no root)
  rules    load and list the detection rules
  sigma    convert upstream Sigma rules into the ARGUS rule format
  baseline build an anomaly baseline from a recorded event stream
  version  print the version

run "argus <command> -h" for a command's flags
`)
}
