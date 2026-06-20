---
name: detection-rules
description: Authoring and reviewing YAML detection rules in rules/*.yaml, mapped to MITRE ATT&CK. Use when adding, editing, or reviewing detections.
---

# Detection rules (ARGUS)

Rules are declarative YAML compiled into a condition tree at load. A rule turns a
behaviour into an alert carrying its ATT&CK technique and severity.

## Anatomy

```yaml
- id: R-0007                       # unique, R-00NN, stable once shipped
  name: Reverse shell from a service process
  description: One sentence on the behaviour and why it's bad.
  severity: critical               # low | medium | high | critical
  risk_score: 90                   # contribution to correlation (optional)
  response: kill                   # optional; default is alert-only
  technique:
    id: T1059
    name: Command and Scripting Interpreter
    tactic: execution
  match:
    all:                           # all | any | not, nested to any depth
      - { field: event.type, op: eq, value: exec }
      - { field: process.parent.name, op: in, value: [nginx, apache2] }
      - { field: process.stdio_socket, op: eq, value: true }
```

## Operators

`eq ne in not_in contains startswith endswith regex gt lt ge le exists cidr`.
String ops need a string value; `in`/`not_in` need a list; numeric comparisons
need a number; `cidr` matches an IP field against a network.

## Rules for writing rules

1. **Only reference real fields.** Every `field:` must exist in
   `internal/model/fields.go`, or the rule fails to load. Add the field there
   first if you need a new one.
2. **Only match events a sensor emits.** A rule on `event.type: open` for a file
   *read* will never fire live, because the openat sensor forwards only writes
   (reads come via the LSM `file_open` hook). Know your telemetry; note any such
   gap in `docs/DETECTIONS.md`.
3. **Map to a real technique** — id, name, and tactic from attack.mitre.org.
4. **Prove it both ways.** Add the triggering event to a replay fixture and run
   `argus replay` to confirm it fires; make sure benign variants do *not*.
5. **Tune for false positives.** Prefer multiple `all` conditions (parent +
   child + context) over a single broad one. `risk_score` should reflect how
   much a single hit should move a process toward an incident (threshold 75).
6. **Severity drives the default response:** `critical` defaults to kill (when
   enforcement is on); set `response:` explicitly to override.

## After adding a rule

- `argus rules --dir rules` lists it and validates the whole set loads.
- Update `docs/DETECTIONS.md` and `docs/ATTACK_COVERAGE.md`.
- IDs are an API: never renumber a shipped rule.
