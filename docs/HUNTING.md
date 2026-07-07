# Threat Hunting with ARQL

Detection rules tell you about the **known**. Hunting lets an analyst search the
event lake for the **unknown** — a hypothesis expressed as a query, answered from
history. ARGUS ships **ARQL** (ARgus Query Language): a small, readable language
over `internal/eventstore`, evaluated against the *same* fields the detection
engine sees (`internal/model/fields.go`), so a hunt and a rule always agree on
what a field means.

Hunting adds no required infrastructure: the default lake is in-memory, no data
is sent anywhere, and a proven hunt converts into a rule in one step.

## The language

```
query     := sequence | simple
simple    := class ("where" expr)? ("|" pipe)*
sequence  := "sequence" ("by" field)? ("within" duration)? ":" stage (";" stage)+
stage     := class ("where" expr)?
pipe      := "where" expr | "limit" int
class     := IDENT                 // an event verb, or "event"/"any" for all classes
expr      := comparison joined by "and" / "or", grouped with "(" ")", negated with "not"
comparison:= field op value | field "in" "(" value ("," value)* ")"
op        := == != > < >= <= =~ contains startswith endswith
field     := dotted path validated against the event schema
duration  := 30s | 5m | 2h | 1d
```

- **Classes** are the event verbs a sensor emits (`exec`, `connect`, `dns`,
  `open`, `ptrace`, …) — `GET /api/hunt/fields` returns the full list. `any` or
  `event` matches every class.
- **Fields** are the dotted paths in `internal/model/fields.go`
  (`process.name`, `process.parent.name`, `destination.port`,
  `dns.question.name`, `user.id`, …). An unknown field is a compile error, never
  a silent empty result.
- `=~` is a regular expression; it is compiled at parse time so a bad pattern is
  reported before the query runs.

### Examples

```sql
-- a shell spawned by a web server
exec where process.name in ("bash","sh","dash") and process.parent.name == "nginx"

-- beaconing to an uncommon port, newest 50
connect where destination.port == 4444 | limit 50

-- DNS names that look like tunnelling
dns where dns.question.name =~ "[a-f0-9]{20,}\\."

-- a download-then-callback chain on one host, within five minutes
sequence by host.name within 5m:
    exec where process.name == "curl";
    connect where destination.port == 4444
```

`sequence` matches an **ordered** chain: each stage must occur after the
previous one, in the same `by` group (e.g. per host), inside the `within`
window. It is how you hunt a kill chain rather than a single event.

## Where the lake lives

Hunting searches an `eventstore.Store`. The store is the seam described in
[`DATA_LAKE.md`](DATA_LAKE.md):

- **single host / dev:** point the agent's `eventstore` output and the server at
  the same backend. With the in-memory default the server lake is empty until you
  wire one up — by design, so "no hits" never hides "not connected".
- **fleet:** agents write to a shared columnar lake (ClickHouse/DuckDB); the
  server hunts over it. Same query, billions of rows.

Wire a durable shared lake on one box:

```yaml
# argus.yaml — the agent records every event into a durable lake
output:
  - { type: eventstore, format: sqlite, path: /var/lib/argus/events.db }
```

```bash
# argus-server hunts over the same lake
argus-server serve --ui-addr 127.0.0.1:9000 \
  --event-store sqlite --event-dsn /var/lib/argus/events.db
```

## API

All hunting endpoints are **read-only** and need no token (like the other read
endpoints); they never change fleet state.

| Method & path | Body / result |
|---|---|
| `GET /api/hunt/fields` | `{ "fields": [...], "classes": [...] }` for autocompletion |
| `POST /api/hunt` | `{ "query": "...", "limit": 200 }` → `{ count, elapsed_ms, events[] \| sequences[][] }` |
| `POST /api/hunt/to-rule` | `{ "query", "id", "name", "severity", "risk_score", "technique": {...} }` → `{ "yaml": "..." }` |

A query that fails to compile returns **400** with the parser's message; a lake
that was never configured returns **503**, not an empty result.

## From hunt to rule

A hunt that proves useful becomes a detection rule with one call. `to-rule`
projects the query's class and `where`/pipe filters into a `match` tree and
returns rule YAML ready to drop into `rules/` and reload. Sequence
hunts describe a temporal chain a single per-event rule cannot express, so they
are rejected with a clear message rather than producing a rule that means
something subtly different.

The conversion is covered by a round-trip test
(`internal/hunt/torule_test.go`): the generated YAML is loaded by the real rule
engine and must fire on a matching event and stay silent on a non-matching one —
the hunt-to-rule path is enforced, not just asserted on text.

## In the console

The **Hunt** screen is a query bar over the lake: run a query, scan the results
table, click a row for the full event, and **Save as rule** to generate the YAML.
A field/class reference is one click away for autocompletion. `⌘/Ctrl+Enter`
runs the query; the command palette (`⌘/Ctrl+K`) jumps to the screen.

## Safety & limits

- A single hunt scans at most `scanCap` (50k) events from a non-pushdown backend
  before filtering, so an open-ended query cannot exhaust memory; columnar
  backends push predicates down instead of scanning.
- Hunting is pure read: it queries history and never issues a response action.
  Turning a hunt into an automated response is the job of SOAR, behind
  the usual `off → dry-run → enforce` gate.
