# Fleet management (the ARGUS control plane)

A single ARGUS agent defends one host. The control plane — `argus-server` — turns
a set of agents into a fleet: it enrolls them, distributes one canonical
ruleset, ingests their alerts, correlates threats *across* hosts, and pushes
commands back down. Agents work standalone; the control plane is opt-in and off
by default.

```
                 ┌──────────────────────── argus-server ───────────────────────┐
   agent (web-01)│  FleetService (gRPC/mTLS)        admin API (HTTP, localhost) │
   agent (db-01) │  ├─ Enroll      ─────► store (agents, alerts, command queues)│
   agent (app-01)│  ├─ Heartbeat   ◄────► commands                              │
        │  mTLS   │  ├─ ReportAlerts ────► cross-host correlation ─► signals     │
        └────────►│  └─ GetRules    ◄──── ruleset (versioned bundle)            │
                 └──────────────────────────────────────────────────────────────┘
```

The agent never trusts the control plane with more authority than it has locally:
a pushed response command can change posture but can **never** escalate past the
agent's own `response.mode`. See [Commands](#commands) and `docs/SAFETY.md`.

## The API

`proto/fleet/v1/fleet.proto` defines four RPCs. Both ends present certificates
signed by the fleet CA, so an agent's identity is its client certificate.

| RPC | Direction | Purpose |
|-----|-----------|---------|
| `Enroll` | unary | Register a host; receive an agent id and the current rules version. |
| `Heartbeat` | unary | Report liveness and counters; receive queued commands. |
| `ReportAlerts` | client stream | Stream alerts and incidents up to the server. |
| `GetRules` | unary | Pull the ruleset, or learn it is already current. |

The generated Go lives in `internal/fleet/fleetpb` and is committed, so the build
needs no `protoc`. The service implementation is `server/api`; the agent-side
client is `internal/fleet`.

## Security model

- **Mutual TLS, TLS 1.3 only.** The server requires and verifies a client
  certificate (`internal/fleet/tls.go`); an unauthenticated peer cannot reach any
  RPC. The peer's common name is recorded in the audit log.
- **Enrollment token.** `argus-server serve --token <secret>` (or
  `ARGUS_ENROLLMENT_TOKEN`) requires every `Enroll` to present a matching token.
  Empty means open enrollment — development only; the server warns at startup.
- **The admin API is not mutually authenticated.** It binds to `127.0.0.1:8080`
  by default and must stay behind localhost or an authenticating proxy. It is for
  operators, never agents.
- **Per-agent certificates in production.** `gen-certs` mints one shared dev
  certificate for convenience. A real fleet issues a distinct client certificate
  per host from a managed CA so certificates can be revoked individually.

## Rule distribution

The server loads `--rules` and validates every file with the *same* engine the
agents run, so it can never ship a ruleset that won't compile. The bundle is
versioned by a content hash. On each heartbeat the agent reports the version it
is running; if it has drifted, the server returns an `UPDATE_RULES` command, the
agent pulls the bundle with `GetRules`, writes it locally, and **hot-swaps the
detection engine without restarting or dropping events** (`pipeline.SetEngine`).
Correlation state survives the swap.

To roll a new ruleset to the fleet, an operator edits the files in `--rules` and
triggers a reload — `POST /api/rules/reload` or `SIGHUP`. The server re-validates,
bumps the version, and every agent converges on its next heartbeat. A reload that
fails validation is rejected and the previous ruleset keeps serving.

## Commands

`Heartbeat` returns commands queued for the agent (operators queue them through
the admin API). The agent applies:

| Kind | Argument | Effect |
|------|----------|--------|
| `UPDATE_RULES` | version | Pull and hot-reload the ruleset. |
| `SET_RESPONSE_MODE` | `off`\|`dry-run`\|`enforce` | Change the response posture at runtime. |
| `KILL_PROCESS` | pid | Kill a process — honouring the local posture (refused while `off`, recorded in `dry-run`). |
| `QUARANTINE` | dest IP | Drop egress to the IP via nftables — honouring the local posture, same as kill. |

A remote `KILL_PROCESS` runs through the same `respond` posture as a local
detection, so the control plane cannot turn an observe-only agent into an
enforcing one without an explicit `SET_RESPONSE_MODE`.

## Cross-host correlation

Per-host correlation already happens in the agent. The control plane adds the
fleet view (`server/correlate`): the same ATT&CK technique seen on enough
distinct hosts within a window raises a **lateral-movement** signal, and many
hosts contacting one destination raises a **C2 fan-in** signal. Signals are
logged and exposed at `GET /api/signals`.

## Quickstart (local demo)

```bash
# 1. Mint a dev CA + server and agent certificates.
argus-server gen-certs --dir ./fleet-certs --dns argus-server

# 2. Run the control plane (gRPC on :8443, admin on 127.0.0.1:8080).
argus-server serve \
  --ca ./fleet-certs/ca.pem \
  --cert ./fleet-certs/server.pem --key ./fleet-certs/server-key.pem \
  --rules ./rules --token s3cr3t

#    …or skip steps 1–2 with ephemeral certs:
#    argus-server serve --dev --rules ./rules --token s3cr3t

# 3. Point an agent at it (configs/argus.yaml → fleet:), then run the agent.
argus run --config /etc/argus/config.yaml

# 4. Inspect the fleet.
curl -s 127.0.0.1:8080/api/agents  | jq
curl -s 127.0.0.1:8080/api/alerts  | jq
curl -s 127.0.0.1:8080/api/signals | jq

# 5. Push a command (e.g. switch one agent to dry-run).
curl -X POST 127.0.0.1:8080/api/agents/<id>/commands \
  -d '{"kind":"SET_RESPONSE_MODE","argument":"dry-run"}'
```

## Admin API

All responses are JSON. Read endpoints are safe to poll for a UI.

| Method & path | Purpose |
|---------------|---------|
| `GET /healthz` | Liveness. |
| `GET /version` | Server version. |
| `GET /api/agents` | Enrolled agents with an `online` flag. |
| `GET /api/alerts?limit=N` | Recent alerts, newest first. |
| `GET /api/signals` | Recent cross-host signals. |
| `POST /api/agents/{id}/commands` | Queue a command (`{"kind":…,"argument":…}`). |
| `POST /api/rules/reload` | Re-read `--rules` and bump the served version. |

## Production notes

- The in-memory store fits a single instance and a demo. The `store.Store`
  interface exists so a database-backed implementation can replace it without
  touching the API layer.
- Put the admin API behind authentication; never expose it to agents or the
  internet.
- Issue and rotate per-agent certificates from a managed CA.
