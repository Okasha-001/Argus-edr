# ARGUS Control Plane — Implementation Record

This file inventories everything built to complete the **fleet control plane**:
the `argus-server` daemon and the agent-side fleet integration, communicating
over gRPC/mTLS. It is the engineering record (files, objects, APIs, tests,
verification). For the how-it-works / how-to-use guide, see
[`docs/FLEET.md`](FLEET.md).

> Scope note: a transport scaffold pre-existed — the `.proto` + generated
> `fleetpb`, mTLS config (`internal/fleet/tls.go`), dev-cert minting
> (`internal/fleet/certs.go`), the in-memory `server/store`, and
> `server/correlate`. Everything below either implements the missing pieces
> (the gRPC service, rule distribution, the agent client, the server binary, the
> agent wiring) or hardens what existed (tests, runtime rule reload).

---

## 1. Capabilities delivered

| # | Capability | Where |
|---|------------|-------|
| 1 | **mTLS enrollment** with shared-token gate and client-cert identity | `server/api`, `internal/fleet` |
| 2 | **Heartbeats** carrying liveness + counters, returning a command queue | `Service.Heartbeat`, `Client.Heartbeat` |
| 3 | **Alert/incident streaming** agent → server (client-streaming RPC) | `Service.ReportAlerts`, `fleet.Reporter` |
| 4 | **Versioned rule distribution** (content-hash), validated with the agent's own engine | `server/ruleset` |
| 5 | **Agent-side rule hot-reload** — lock-free engine swap, no restart | `pipeline.SetEngine`, `cmd/argus/fleet.go` |
| 6 | **Runtime rule reload on the server** (`POST /api/rules/reload`, `SIGHUP`) | `cmd/argus-server` |
| 7 | **Cross-host correlation** (lateral movement, C2 fan-in) → signals | `server/correlate` (+ tests) |
| 8 | **Pushed commands**: update rules, set response mode, kill, quarantine | `cmd/argus/fleet.go`, `respond` |
| 9 | **Admin HTTP API** for fleet visibility + command/reload control | `cmd/argus-server/admin.go` |
| 10 | **Graceful lifecycle** — clean shutdown, report flush, reconnect | `serve.go`, `fleet.Reporter` |
| 11 | **Safety**: a remote command can't escalate past local `response.mode` | `respond.RequestKill` |

---

## 2. New files (non-test) — 11 files, 1368 LOC

| File | LOC | Purpose |
|------|----:|---------|
| `server/ruleset/ruleset.go` | 106 | Versioned rule `Provider`: load + validate + content-hash + reload. |
| `server/api/service.go` | 155 | The `FleetService` gRPC server (Enroll/Heartbeat/ReportAlerts/GetRules). |
| `server/api/convert.go` | 68 | store↔proto mapping, command-kind mapping, mTLS peer identity. |
| `internal/fleet/client.go` | 168 | Agent transport client: Dial, Enroll, Heartbeat, FetchRules, Report. |
| `internal/fleet/reporter.go` | 131 | Buffered, non-blocking alert stream pump with reconnect + shutdown flush. |
| `internal/fleet/report.go` | 51 | `model.Alert`/`Incident` → `fleetpb.AlertReport` conversion. |
| `cmd/argus-server/serve.go` | 182 | Wire gRPC/mTLS + admin HTTP; SIGHUP reload; graceful shutdown. |
| `cmd/argus-server/admin.go` | 165 | JSON admin API (agents, alerts, signals, commands, rule reload). |
| `cmd/argus-server/gencerts.go` | 35 | `gen-certs` subcommand (dev CA + server/agent certs). |
| `cmd/argus-server/main.go` | 55 | Subcommand dispatch (rewritten from the HTTP-only scaffold). |
| `cmd/argus/fleet.go` | 252 | Agent fleet runner + fleet `Sink` + command application + rule sync. |

## 3. New test files — 8 files, 875 LOC

| File | LOC | Covers |
|------|----:|--------|
| `server/api/service_test.go` | 279 | **End-to-end over real mTLS**: enroll/token, heartbeat+commands, GetRules changed/unchanged, ReportAlerts → cross-host signal. |
| `server/ruleset/ruleset_test.go` | 99 | Versioning, stability, change-on-edit, invalid-rule rejection, last-good-bundle on failed reload. |
| `internal/pipeline/setengine_test.go` | 112 | Mid-stream engine swap (gated source) actually changes which rules fire. |
| `server/store/memory_test.go` | 85 | Enroll/get/heartbeat, online TTL, command queue, alert order + cap. |
| `internal/fleet/certs_test.go` | 96 | mTLS handshake succeeds; server rejects a client with no certificate. |
| `internal/fleet/report_test.go` | 70 | Alert/incident → proto field mapping. |
| `internal/respond/responder_test.go` | 71 | `RequestKill` honours posture; `SetMode` round-trip; `Mode.String`. |
| `server/correlate/crosshost_test.go` | 63 | Lateral movement fires once at threshold; C2 fan-in; window expiry; empty keys. |

## 4. Modified files

| File | Change |
|------|--------|
| `cmd/argus/run.go` | Split `buildEngine` → `buildCorrelator`/`loadEngine`; assemble fleet sink; start/drain the fleet runner; cancel ctx on pipeline stop. |
| `internal/config/config.go` | New `Fleet` config struct + field + defaults. |
| `internal/config/validate.go` | `validateFleet` (required fields when enabled). |
| `internal/config/config_test.go` | Fleet validation tests. |
| `internal/respond/responder.go` | Atomic runtime mode; `Mode()`, `SetMode()`, `RequestKill()`. |
| `internal/respond/policy.go` | `Mode.String()`. |
| `internal/pipeline/pipeline.go` | Engine held in `atomic.Pointer`; `SetEngine()`. |
| `configs/argus.yaml` | Documented `fleet:` block (disabled by default). |
| `docs/FLEET.md` *(new)* | User-facing fleet guide. |
| `docs/ROADMAP.md`, `CLAUDE.md` | Moved Fleet to "Done"; updated the architecture map. |

---

## 5. Objects / types (public surface)

**`server/ruleset`** — `Provider` (`NewProvider`, `Reload`, `Version`, `Bundle`), `File{Name, Content}`.

**`server/api`** — `Service` (implements `FleetServiceServer`), `Deps{Store, Rules, Correlator, Token, OnSignal, Logger, Clock}`, `New(Deps)`.

**`internal/fleet`** (agent transport) — `Client` (`Dial`, `Enroll`, `Heartbeat`, `FetchRules`, `Report`, `Close`, `NewReporter`); `Reporter` (`Enqueue`, `Run`, `Dropped`); `ClientConfig`, `Stats`, `Command`, `EnrollResult`, `RuleFile`, `Rules`; `AlertReportFromAlert`, `AlertReportFromIncident`.

**`server/store`** *(pre-existing)* — `Store` interface, `Memory`, `Agent`, `Stats`, `AlertRecord`, `Command`.

**`server/correlate`** *(pre-existing)* — `CrossHost` (`Observe`), `Signal`, kinds `KindLateralMovement`, `KindC2FanIn`.

**`cmd/argus` (agent)** — `fleetConn`, `fleetSink` (implements `output.Sink`), `fleetRunner` (heartbeat loop + command application + `syncRules`).

**`cmd/argus-server`** — `adminAPI`, subcommands `serve` / `gen-certs`.

---

## 6. gRPC API — `FleetService` (`proto/fleet/v1/fleet.proto`)

| RPC | Type | Purpose |
|-----|------|---------|
| `Enroll` | unary | Register a host; return agent id + current rules version. |
| `Heartbeat` | unary | Report counters; return queued commands (incl. auto `UPDATE_RULES` on drift). |
| `ReportAlerts` | client-stream | Stream alerts/incidents up; correlate; ack the count. |
| `GetRules` | unary | Pull the ruleset, or report `unchanged`. |

Both ends present certificates signed by the fleet CA (TLS 1.3, `RequireAndVerifyClientCert`). Generated Go is committed in `internal/fleet/fleetpb` — **no `protoc` at build time**.

---

## 7. Admin HTTP API (`cmd/argus-server/admin.go`)

Binds to `127.0.0.1:8080` by default (not mutually authenticated — keep local).

| Method & path | Purpose |
|---------------|---------|
| `GET /healthz`, `GET /version` | Liveness / version. |
| `GET /api/agents` | Enrolled agents + `online` flag. |
| `GET /api/alerts?limit=N` | Recent alerts, newest first. |
| `GET /api/signals` | Recent cross-host signals. |
| `POST /api/agents/{id}/commands` | Queue a command `{"kind":…,"argument":…}`. |
| `POST /api/rules/reload` | Re-read `--rules`, bump version (agents converge next heartbeat). |

---

## 8. Command-line surface

```
argus-server serve      --grpc :8443 --http 127.0.0.1:8080 --rules ./rules \
                        --ca … --cert … --key …   (or --dev)  --token <secret>
                        --correlate-window 5m --correlate-min-hosts 3 --heartbeat-ttl 90s
argus-server gen-certs  --dir ./fleet-certs --dns argus-server
argus run               # agent; fleet activated by the config's fleet.enabled
```

## 9. Agent configuration (`fleet:` block, off by default)

```yaml
fleet:
  enabled: false
  server_address: argus.example.com:8443
  server_name: argus.example.com
  ca_file: /etc/argus/fleet/ca.pem
  cert_file: /etc/argus/fleet/agent.pem
  key_file: /etc/argus/fleet/agent-key.pem
  enrollment_token: ""
  heartbeat_seconds: 30
```

---

## 10. Pushed commands

| Kind | Argument | Effect (agent side) |
|------|----------|---------------------|
| `UPDATE_RULES` | version | Pull + hot-reload ruleset (`SetEngine`). |
| `SET_RESPONSE_MODE` | `off`\|`dry-run`\|`enforce` | Change posture at runtime. |
| `KILL_PROCESS` | pid | Kill — **honouring local posture** (refused while `off`). |
| `QUARANTINE` | dest IP | Drop egress to the IP via nftables — **honouring local posture**. |

**Safety invariant:** a remote command can never enforce on an agent whose local
`response.mode` is `off`; the control plane can only request, never escalate.

---

## 11. Verification

All from the user-local toolchain (Go 1.26, `GOTOOLCHAIN=local GOFLAGS=-mod=mod`).

- `go build ./...` — clean
- `go vet ./...` — clean
- `go test ./... -race` — **11 packages pass, race-clean**
- `golangci-lint run ./...` — **0 issues**
- `gofmt -l` — clean; `go mod tidy` — no diff

**End-to-end smoke (real binaries, `--dev`):** agent enrolled over mTLS, ran the
kill-chain (5 alerts + 2 incidents), streamed them up; admin API showed the agent
and forwarded alerts at full fidelity; command enqueue returned 202/400/404.

**UPDATE_RULES hot-reload demo (long-lived agent via a FIFO replay source):**

```
control plane up, rules_version = 089afd13c9a9            (V1)
agent enrolled over mTLS
BEFORE: canary processed; R-9999 alerts = 0; canary rule file = 0
POST /api/rules/reload -> {"status":"reloaded","version":"b4bd49642a93"}  (V2)
agent hot-reloaded: "applied pushed ruleset" version=b4bd49642a93 files=6
AFTER:  ALERT [HIGH] R-9999 Canary hot-reload rule (T1059) — pid=5002 canaryproc
control plane received: host=web-01 rule=R-9999 sev=high pid=5002 technique=T1059
```

---

## 12. Known gaps / next

- In-memory store only (the `store.Store` interface is ready for a DB backend).
- Admin API is unauthenticated — localhost / behind a proxy only; RBAC + audit next.
- One shared dev agent certificate; production needs per-agent issuance + rotation.
- A web UI can be built directly on the admin API.
