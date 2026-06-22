# SOAR & Response Playbooks (Platform v2 — Phase 17)

SOAR connects detection to action: when an alert matches a playbook's trigger,
ARGUS works its steps — notify a human, open a case, run a hunt for context, or
ask an agent to kill or quarantine. It is built to be **safe by default** and
fully self-hosted, with no required or paid integration.

This is Phase 17 of `docs/PLATFORM_V2_MASTER_PLAN.md`. Read `docs/SAFETY.md`
first — automation that can kill processes deserves the same care as the response
engine it drives.

## Three gates, all off by default

Nothing acts unless three independent gates are open:

1. **The engine is off** until `--soar` (or `POST /api/soar/enable`). While off,
   no playbook runs, whatever its mode.
2. **Every playbook defaults to dry-run.** A dry-run playbook logs what it *would*
   do and executes only read-only steps (a hunt); notify/open-case/kill/quarantine
   are recorded, not performed. A playbook acts only in `enforce`.
3. **The agent clamps host actions.** kill/quarantine are *requests* queued to an
   agent, which still honours its local `response.mode` (off by default). An
   enforce playbook can never push an agent past its own posture.

So even a fully "armed" engine running an enforce playbook cannot harm a
default-configured agent. Promote deliberately, and rehearse first.

## Playbooks

A playbook is a trigger plus ordered steps (`server/soar`):

```jsonc
{
  "name": "Contain reverse shell",
  "mode": "dry-run",                         // off | dry-run | enforce
  "trigger": { "severities": ["critical"], "min_risk": 80, "incidents_only": true },
  "steps": [
    { "type": "notify" },                    // -> configured integrations
    { "type": "run_hunt", "query": "connect where destination.port == 4444" },
    { "type": "open_case" },                 // -> server/cases
    { "type": "kill_process" }               // -> agent (clamped by response.mode)
  ]
}
```

Trigger fields are ANDed; an empty field is a wildcard. Steps:

| Step | Effect | Runs in dry-run? |
|------|--------|------------------|
| `notify` | send to webhook/Slack/SMTP/syslog | no (recorded) |
| `open_case` | open an investigation case | no (recorded) |
| `run_hunt` | ARQL query for context (read-only) | **yes** |
| `kill_process` | queue KILL for the alert's pid | no (recorded) |
| `quarantine` | queue network block for the dst IP | no (recorded) |

## Integrations (`internal/integrations`)

All optional, all self-hosted-friendly, none required or paid:

| Flag | Destination |
|------|-------------|
| `--notify-webhook URL` | generic JSON POST |
| `--notify-slack URL` | Slack or Mattermost incoming webhook |
| `--notify-syslog host:port` | RFC 3164 over UDP to a collector |
| `--notify-smtp host:port` + `--notify-from` + `--notify-to` | email |

These are the only components that make an outbound connection, and only to an
endpoint you configured — the zero-phone-home promise holds (Phase 21).

## API

| Method & path | Purpose |
|---|---|
| `GET /api/soar/status` | engine enabled? playbook count |
| `POST /api/soar/enable` `{enabled}` | flip the global switch (audited) |
| `GET /api/soar/runs` | recent run records (newest first) |
| `GET/POST /api/playbooks` | list / create (create defaults to dry-run) |
| `GET/PUT/DELETE /api/playbooks/{id}` | read / update / delete (audited) |
| `POST /api/playbooks/{id}/test` `{alert_id?}` | **rehearse** in forced dry-run against a real alert |

Every mutation is written to the admin audit log. Bind the admin API to localhost
or an authenticating proxy.

## In the console

The **Automation** screen shows the engine switch, the playbook table (with a
simple step builder in the drawer), and a recent-runs panel. **Test** rehearses a
playbook in forced dry-run and shows each step's outcome — the mandatory dry-run
before you switch it to enforce.

## Recommended rollout

1. Author a playbook (it starts in dry-run).
2. **Test** it against a real incident; read every outcome.
3. Enable the engine (`--soar`); confirm dry-run runs look right in *Recent runs*.
4. Only then set the playbook to `enforce` — and only on agents whose
   `response.mode` you intend to allow to act.
