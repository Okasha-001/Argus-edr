# Contributing to ARGUS

Thanks for helping build ARGUS. This is the short set of engineering
expectations for changes to the agent, control plane, rules, and documentation.

## Before you start

- Read the README and the subsystem document for the area you are changing.
- Enforcement work additionally requires reading `docs/SAFETY.md`.

## Build and check

```bash
make all        # compile eBPF objects + Go binaries
make fmt        # gofmt + clang-format
make vet lint   # go vet + golangci-lint
make test       # go test ./...
make replay     # end-to-end sanity over the recorded kill chain
```

Every change must leave `make fmt vet lint test` green.

## Standards

- **Clean code:** small single-purpose functions, intention-revealing names,
  errors wrapped with context, and comments that explain *why*.
- **The ABI invariant:** if you change `struct event` in `bpf/common.h`, update
  `internal/decode/wire.go` (offsets + `WireSize`), the `EventType` enums in both
  languages, and `wire_test.go`, in the same commit.
- **No machine-specific or personal data** in committed files — no usernames,
  home paths, emails, real hostnames or internal IPs. Use neutral placeholders.
- **Tests with behaviour changes.** New detections need a replay fixture that
  proves they fire (and that benign variants don't).

## Commits and PRs

- Small, focused commits with imperative messages ("add ptrace sensor", not
  "changes").
- One logical change per PR; describe what and why, and how you tested it.
- Keep CI green.

## Reporting security issues

Please report suspected vulnerabilities privately to the maintainers rather than
opening a public issue.
