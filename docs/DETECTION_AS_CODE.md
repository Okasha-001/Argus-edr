# Detection-as-Code (Platform v2 — Phase 16)

Detections in ARGUS are code: versioned, tested, signed, and measured. Phase 16
turns the rule set into an ecosystem — a test harness that proves every rule
behaves, shareable signed rule packs, a Sigma importer, and a live ATT&CK
coverage view — all FOSS and offline.

This is Phase 16 of `docs/PLATFORM_V2_MASTER_PLAN.md`.

## Rule tests (`make test-rules`)

Every rule ships with fixtures that prove it **fires** on the behaviour it
targets and stays **silent** on a benign look-alike. A fixture is YAML using the
same JSON event shape the agent sees:

```yaml
- name: binary run from /tmp fires R-0001
  rule: R-0001
  expect: fire
  event: { action: exec, process: { name: x, executable: /tmp/.x/payload } }
- name: system binary does not fire R-0001
  rule: R-0001
  expect: no-fire
  event: { action: exec, process: { name: ls, executable: /usr/bin/ls } }
```

Fixtures live in `rules/tests/*.yaml`. The harness (`internal/detect/test_harness.go`)
loads the rules, replays each fixture's events through the real rule logic
(`Rule.Matches`, the same path production uses), and reports:

```
$ make test-rules
rule tests: 114/114 passed · 0 false positive(s) · 0 false negative(s) · FP rate 0.0%
coverage: 57/57 rules have at least one test
```

- A **false positive** is a `no-fire` fixture that fired (a rule crying wolf); a
  **false negative** is a `fire` fixture that did not (a rule gone blind).
- `--max-fp-rate` fails the build above a threshold (default: zero tolerance).
- `--require-coverage` fails if any rule has no test, so new rules arrive with
  fixtures.
- A fixture naming an unknown rule id fails — a typo or a deleted rule cannot
  leave a test quietly green.

`make test-rules` is the gate; wire it into CI alongside `make test`.

## Rule packs

A **rule pack** is shareable, versioned detection content: a directory with a
`pack.yml` manifest and one or more `*.yaml` rule files. The `.yml` manifest is
skipped by the rule loader's `*.yaml` glob, so the same directory loads cleanly
as rules.

```
rules/packs/community-linux/
  pack.yml          # name, version, description, author
  rules.yaml        # C-* namespaced rules
```

`detect.LoadPack(dir)` validates the manifest, compiles the rules, and computes a
**content digest** (SHA-256 over the manifest and every rule file). The digest is
signed with **ed25519**:

```go
pack, _ := detect.LoadPack("rules/packs/community-linux")
signature := pack.Sign(authorPrivateKey)        // author keeps the private key
err := pack.Verify(signature, authorPublicKey)  // consumer checks before trusting
```

A pack whose rules changed after signing fails verification, so a consumer knows
content arrived unaltered. Private keys are never committed — the round-trip test
generates an ephemeral key pair.

## ATT&CK coverage

The **Detections** screen renders a Navigator-style matrix: one column per tactic
(in kill-chain order), each technique shaded by how many rules cover it. For the
full tool, **Download ATT&CK layer** exports a
[MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer
(`GET /api/detections/navigator`) that imports directly into the public
Navigator — generated from the served ruleset, scored by rule count.

## Sigma import

`argus sigma [-o out.yaml] PATH...` converts upstream
[Sigma](https://github.com/SigmaHQ/sigma) rules to native ARGUS rules
(`internal/sigma`). Supported field modifiers: `contains`, `startswith`,
`endswith`, `re`, `cidr`, `all`, and the numeric comparisons `gt`/`gte`/`lt`/`lte`
(mapped to the ARGUS `gt`/`ge`/`lt`/`le` operators). Unsupported features are
reported as typed errors and skipped in bulk import, never silently dropped. The
converter validates regex and CIDR values at import, so **convert-success implies
the output loads** — enforced by `FuzzConvert`.

## The loop

Hunting (Phase 14) finds the unknown; **Save as rule** turns a proven hunt into
rule YAML; a fixture pins its behaviour; `make test-rules` keeps it honest; a pack
shares it, signed; the Navigator shows where it lands on ATT&CK. Detection is
code, all the way round.
