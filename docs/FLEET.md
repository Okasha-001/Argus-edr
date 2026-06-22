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
- **The admin API binds to `127.0.0.1:8080`** by default and must stay behind
  localhost or an authenticating proxy — it is for operators, never agents. Its
  **state-changing endpoints (command enqueue, rule reload) require a bearer
  token**: `argus-server serve --admin-token <secret>` (or `ARGUS_ADMIN_TOKEN`),
  presented as `Authorization: Bearer <secret>`. With no token configured those
  endpoints are **refused** (`503`), so there is never an unauthenticated path to
  kill or quarantine a host; read-only endpoints stay open for local dashboards.
  Every command and reload is written to the audit log with its source address.
- **Response actions honour the agent's `max_mode` ceiling.** A pushed
  `SET_RESPONSE_MODE`/`KILL`/`QUARANTINE` can never enforce on a host whose local
  `response.max_mode` forbids it (see `docs/SAFETY.md`).
- **Each agent is bound to its certificate.** At enrollment the server records
  the SHA-256 of the agent's client certificate; every later heartbeat, alert
  report and command drain must present that same certificate, or the request is
  rejected with `PermissionDenied`. This stops one valid fleet certificate from
  impersonating another agent (spoofing heartbeats, stealing its commands, or
  filing alerts under its name).
- **Per-agent certificates in production.** Because identity is pinned per
  certificate, give each host its own. `gen-certs --agents web-01,db-01` mints a
  distinct certificate per host (and still writes a shared `agent.pem` for demos);
  a real fleet issues them from a managed CA so each can be revoked individually.
  The shared dev certificate makes every agent share one identity, so the binding
  only distinguishes hosts once they have per-agent certificates.

## Certificate rotation

Per-agent certificates expire, leak, or simply need rolling. The control plane
rotates one **without losing the agent's enrolled identity** and without locking
it out. Rotation needs the CA key, so start the server with `--ca-key` (always
available under `--dev`); otherwise the endpoint is disabled (`501`).

The flow is a staged overlap, not a cut-over:

1. An admin calls `POST /api/agents/{id}/rotate-cert`. The server mints a fresh
   client certificate from the CA, **stages its fingerprint as the agent's
   pending identity** (the current one keeps working), and returns the new
   keypair in the response.
2. The operator delivers the returned `cert`/`key` to the host, replacing its
   certificate files. The agent reloads its client certificate from disk on the
   next reconnect — `internal/fleet` builds the client TLS with a reloader, so no
   restart or config change is required (a restart also works).
3. When the agent next connects presenting the new certificate, the server
   recognises the pending fingerprint, **promotes it to the sole identity, and
   drops the old one**. From then on the previous certificate is rejected with
   `PermissionDenied`.

Because both certificates are accepted only during the window between staging and
the agent's first reconnect, a rotation is safe to start at any time: a slow or
offline agent keeps authenticating with its old certificate until it actually
adopts the new one. The new private key crosses the wire once, on the token-gated,
audited, localhost admin API — the same trust boundary as `gen-certs`. Every
rotation is written to the audit log.

```bash
# Rotate web-01's certificate, capturing the new keypair.
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://127.0.0.1:8080/api/agents/$AGENT_ID/rotate-cert > rotated.json
jq -r .cert rotated.json > web-01.pem
jq -r .key  rotated.json > web-01-key.pem
# Deliver web-01.pem / web-01-key.pem to the host's fleet cert/key paths.
```

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

## Policy distribution

The bundle can carry more than rules: a **policy** document (`--policy-file`, or
`ARGUS_POLICY_FILE`) distributes posture — today the fleet-wide `response.mode`.
The server validates it at load (an invalid policy refuses the reload, exactly
like a broken rule) and folds it into the same content hash, so a posture change
bumps the version and converges on the next heartbeat. It rides in the bundle as
the reserved `argus-policy.yml` entry, which the agent's `*.yaml` rule glob
ignores, so it never lands in the rules directory.

An agent applies the policy through its responder, which clamps the pushed mode
to the host's local `response.max_mode` ceiling. A policy can therefore **lower**
posture across the fleet but can **never** escalate past what the operator pinned
on a host — the same safety invariant as a pushed `SET_RESPONSE_MODE`. A policy
that fails to parse is logged and skipped on the agent, never fatal. See
`configs/policy.sample.yml` for the format and `docs/SAFETY.md` for the ceiling.

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
  --rules ./rules --token s3cr3t --admin-token adm1n

#    …or skip steps 1–2 with ephemeral certs:
#    argus-server serve --dev --rules ./rules --token s3cr3t --admin-token adm1n

# 3. Point an agent at it (configs/argus.yaml → fleet:), then run the agent.
argus run --config /etc/argus/config.yaml

# 4. Inspect the fleet.
curl -s 127.0.0.1:8080/api/agents  | jq
curl -s 127.0.0.1:8080/api/alerts  | jq
curl -s 127.0.0.1:8080/api/signals | jq

# 5. Push a command (e.g. switch one agent to dry-run). Needs the admin token.
curl -X POST 127.0.0.1:8080/api/agents/<id>/commands \
  -H 'Authorization: Bearer adm1n' \
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
