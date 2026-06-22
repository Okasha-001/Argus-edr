# Investigation: Attack Graph & Case Management (Platform v2 — Phase 15)

When a host lights up, an analyst needs two things fast: to **see the story** and
to **work it**. Phase 15 adds both — a reconstructed attack graph and a forensic
timeline, plus a case manager to assign, discuss, gather evidence, and export a
report. It builds on the event lake (Phase 14) and reuses the triage narrative
(Phase 9) so a finished investigation reads as one coherent account.

This is Phase 15 of `docs/PLATFORM_V2_MASTER_PLAN.md`. It adds no required
infrastructure, sends nothing out, and keeps every report free of machine- or
developer-specific data.

## Attack graph (`server/investigate`)

`investigate.Build` is a pure transform: given a host's events and the
detection annotations that touch them, it returns nodes and causal edges.

- **Nodes** — processes, files, and network endpoints seen in the window.
- **Edges** — `spawned` (a process forked/exec'd a child), `opened`/`deleted`/
  `renamed`/`chmod` (a process touched a file), `connected`/`resolved` (a process
  reached out). Identical edges collapse, so a noisy loop is one line.
- **ATT&CK overlay** — each process node carries the techniques of the alerts
  that fired on its PID and the highest severity touching it, so the graph shows
  *where* in the chain the detections landed.

It is decoupled by design: it takes plain `[]*model.Event` and a slice of
`Annotation{PID, TechniqueID, Severity}`, so it depends on neither the event lake
nor the control-plane store. The admin API wires those in:

```
GET /api/investigate/graph?host=web-01[&since=RFC3339]
  -> { host, nodes:[{id,kind,label,pid,techniques,severity,alerting}], edges:[{source,target,kind}] }
```

The console lays the graph out left-to-right by causal depth (root processes
first, children deeper, the files and endpoints they touched one step further)
and renders it as dependency-free SVG — no graph library, no CDN.

## Case management (`server/cases`)

A **case** groups the alerts of an incident into a unit a team can work:

| Operation | Endpoint |
|---|---|
| open | `POST /api/cases` `{title, severity, host, tags, evidence}` |
| list | `GET /api/cases[?status=&assignee=]` |
| read | `GET /api/cases/{id}` |
| assign | `POST /api/cases/{id}/assign` `{assignee}` |
| status | `POST /api/cases/{id}/status` `{status: open\|triage\|closed}` |
| comment | `POST /api/cases/{id}/comments` `{author, body}` |
| evidence | `POST /api/cases/{id}/evidence` `{alert_ids:[...]}` |
| report | `GET /api/cases/{id}/report` -> `{report: "<markdown>"}` |

The `Store` interface keeps the default **in-memory** backend (single-binary
mode) swappable for a durable one, exactly as `server/store` and
`internal/eventstore` began. Evidence de-duplicates; mutations are timestamped
and written to the admin **audit log**.

Case management is analyst workflow — it groups alerts and never touches an agent
or the fleet — so, like the other read endpoints, it stays usable in
single-binary mode without a token, while the fleet's kill/quarantine endpoints
remain token-gated (Phase 8). Bind the admin API to localhost or put it behind an
authenticating proxy, as its documentation states.

## Reports

`GET /api/cases/{id}/report` renders the case as a self-contained Markdown
document: header, the triage **summary** and **containment** (from
`internal/triage`, so it matches the console's triage panel), an **evidence**
table resolved from the attached alerts, and the **notes** thread. It contains
only case data, alert metadata and templated prose — never a username, home path
or internal address — so it is safe to attach to a ticket. A round-trip test
asserts the structure and that the evidence resolves.

## In the console

The **Investigation** screen takes a host, draws its attack graph and timeline
side by side, and lists cases below. **New case** opens one (pre-filled from the
host); clicking a case opens a drawer to assign it, move its status, add notes,
and **Generate report**. Clicking a graph node shows its details.

## Safety & scope

Investigation is read and annotate only. It surfaces what happened and lets an
analyst organise it; it never issues a response. Turning an investigation into an
automated action is SOAR (Phase 17), behind the `off → dry-run → enforce` gate.
