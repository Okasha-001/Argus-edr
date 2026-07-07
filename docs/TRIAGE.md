# Incident triage

ARGUS turns a structured incident into an analyst-ready triage report: a
natural-language **summary**, a **severity**, concrete **containment steps**, and
an optional **detection-rule draft**. Triage runs in the control plane and is
surfaced on the console's incident timeline and over the admin API.

It ships with a built-in offline template provider (`internal/triage.Summarizer`):

| Provider | Network | When |
|----------|---------|------|
| `template` (default) | none | Deterministic report built from the incident's own fields. The default, and the path every test exercises. |

**Privacy posture:** The triage provider is fully offline. No incident data leaves the local process.

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
