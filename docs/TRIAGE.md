# Incident triage

ARGUS turns a structured incident into an analyst-ready triage report: a
natural-language **summary**, a **severity**, concrete **containment steps**, and
an optional **detection-rule draft**. Triage runs in the control plane and is
surfaced on the console's incident timeline and over the admin API.

It ships with two providers behind one interface (`internal/triage.Summarizer`):

| Provider | Network | When |
|----------|---------|------|
| `template` (default) | none | Deterministic report built from the incident's own fields. The default, and the path every test exercises. |
| `claude` | calls the Claude API | A richer LLM narrative, used only when an operator turns it on **and** supplies a key. |

**Privacy posture (the golden rule for this feature):** no incident data leaves
the process unless the operator explicitly selects the `claude` provider *and*
sets an API key. The template provider is fully offline. If the Claude provider
is enabled but the call fails — a network error, a bad key, or a safety
**refusal** — triage falls back to the template report, so a misconfiguration
degrades gracefully and never breaks the request.

## Using it

The console's **Incident timeline** shows a **Triage** button on every incident
node. Click it to fetch the report for that incident and render it below the
chain. Over the API directly:

```bash
curl -s http://127.0.0.1:8080/api/alerts/$INCIDENT_ID/triage | jq
{
  "summary": "Host web-01: process kdevtmpfsi (pid 4200) accumulated risk 90 …",
  "severity": "critical",
  "containment": [
    "Kill the offending process kdevtmpfsi (pid 4200) and isolate web-01 …",
    "Block egress from web-01 and capture the destination for threat-intel.",
    "Snapshot web-01 and preserve volatile memory before remediation."
  ],
  "rule_draft": "",
  "source": "template"
}
```

The endpoint is read-only: it produces analysis and queues nothing. It
reconstructs the incident's context from the host's recent alerts and reads each
technique's ATT&CK tactic from the **served ruleset itself**, so containment
advice stays in sync with the rules that fired.

## Enabling the Claude provider

```bash
export ANTHROPIC_API_KEY=sk-ant-…          # the key is read from the env, never a flag or config file
argus-server serve --triage claude \
  --rules ./rules --ca … --cert … --key … --admin-token …
# optional: --triage-model claude-opus-4-8   (defaults to the latest Opus)
```

The model defaults to the latest Opus (`claude-opus-4-8`). The request is a
single, minimal Messages API call over `net/http` (no SDK dependency), asking the
model for a JSON triage report; ARGUS validates and renders it. The summary
`source` field tells the analyst whether they are reading a `template` or a
`claude` report.

## Safety notes

- **Off by default.** `--triage` defaults to `template`. Nothing reaches an
  external service until you opt in.
- **The key never lands in a committed file.** It is read from
  `ANTHROPIC_API_KEY`, consistent with ARGUS's no-secrets-in-config rule.
- **Refusals are expected on security content.** Opus safety classifiers can
  decline a prompt that describes an attack; ARGUS treats a refusal like any
  other failure and returns the template report.
- Incident data sent to the Claude provider is the structured incident only
  (host, process, risk, techniques, alert names) — never raw event payloads.
