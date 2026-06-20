# Importing Sigma rules

[Sigma](https://github.com/SigmaHQ/sigma) is the community standard for sharing
detection logic. ARGUS can convert Sigma rules into its own rule format so you
can pull from the public ruleset instead of writing every detection by hand.

```bash
# Convert one or more files / directories into a single ARGUS rule file.
argus sigma -o /etc/argus/rules/50-sigma.yaml ./sigma/rules/linux/

# Or preview on stdout.
argus sigma rules/sigma/
```

The importer recurses into directories, picking up `*.yml` and `*.yaml` files. It
prints a one-line summary (`converted N rules, skipped M`) to stderr and writes
the converted rules — a normal ARGUS rule bundle — to `-o` (or stdout). The
output loads through the same loader the agent and the fleet use, so an imported
file is a first-class rule file: drop it in `detection.rules_dir`.

## What is supported

ARGUS targets Linux endpoint telemetry, so the importer maps the Sigma features
that have an ARGUS equivalent and **skips the rest cleanly** rather than emitting
a rule that would never (or wrongly) match.

**Log sources** → the converted rule is anchored to the matching ARGUS event, so
it only fires on events of that kind:

| Sigma `logsource.category` | ARGUS event |
|----------------------------|-------------|
| `process_creation` | `exec` |
| `network_connection` | `connect` |
| `dns_query` | `connect` (matched on the queried name) |
| `file_event` | `open` |
| `file_change` | `chmod` |
| `file_delete` | `unlink` |
| `file_rename` | `rename` |

**Fields** are translated to ARGUS rule fields — `Image`→`process.executable`,
`CommandLine`→`process.command_line`, `ParentImage`→`process.parent.executable`,
`User`→`user.name`, `DestinationIp`→`destination.ip`, `TargetFilename`→
`file.path`, `sha256`→`process.hash.sha256`, and so on.

**Value modifiers**: `contains`, `startswith`, `endswith`, `re` (regex), `cidr`
and `all`. Plain values with `*` / `?` wildcards are translated automatically
(`*foo*`→contains, `foo*`→startswith, an interior wildcard→an anchored regex).

**Conditions**: `and` / `or` / `not`, parentheses, and the `all of …`, `1 of …`
and `any of …` quantifiers over `them` or a `prefix*` pattern. A list of values
is OR-ed by default, or AND-ed under the `|all` modifier.

## What is skipped

A rule is skipped (with a note naming the reason) when it uses something outside
that subset — most commonly:

- a non-Linux `logsource.product` (e.g. `windows`),
- an unsupported category (registry, WMI, …) or a field ARGUS does not collect,
- keyword / full-text selections, or an unsupported value modifier (`base64`, …),
- a counted quantifier such as `2 of selection_*`, which a boolean tree cannot
  express.

Skipping is per-rule, so importing a large upstream directory yields every rule
ARGUS *can* run and a tally of what it could not — convert first, then review the
skips.

## Generated metadata

- **id** — `SIGMA-` + the first 8 hex of the Sigma UUID (or a title hash).
- **severity / risk** — from the Sigma `level` (`informational`/`low`→low,
  `medium`→medium, `high`→high, `critical`→critical).
- **technique** — from the `attack.tXXXX[.YYY]` and `attack.<tactic>` tags.

`rules/sigma/` in this repo holds a few example Sigma sources you can convert to
see the workflow end to end.
