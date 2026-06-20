# Threat intelligence (IOC feeds)

ARGUS can match every event against a set of threat-intelligence indicators —
known-malicious IPs, network ranges, domains and file hashes — and raise an
alert the moment one appears. This complements the behavioural rules: rules catch
*what a process does*, indicators catch *who it talks to* and *what it is*.

The feature is **off by default**. A standalone agent runs purely on behavioural
detection until you point it at one or more feeds.

## Feed format

A feed is a newline-delimited text file. Each non-blank, non-comment line is one
indicator, and its type is inferred:

| Looks like | Inferred type | Matched against |
|------------|---------------|-----------------|
| contains `/` and parses as a network | CIDR range | `source.ip`, `destination.ip` |
| parses as an IP (v4 or v6) | IP | `source.ip`, `destination.ip` |
| 64 hex characters | SHA-256 hash | `process.hash.sha256` |
| anything else | domain | `dns.question.name` |

`#` starts a comment (whole-line or trailing); blank lines are ignored. Hashes and
domains are matched case-insensitively. See `configs/intel/iocs.sample.txt` for a
worked example.

```text
203.0.113.66            # a single C2 address
203.0.113.0/24          # a whole malicious range
c2.malware.example      # a domain
44d88612fea8a8f36de82e1278abb02f...  # a SHA-256 file hash
```

> Hash matching only fires when executables are hashed: set
> `enrichment.hash_executables: true` so `process.hash.sha256` is populated.

## Enabling it

```yaml
# /etc/argus/config.yaml
intel:
  enabled: true
  feeds:
    - /etc/argus/intel/iocs.txt
    - /etc/argus/intel/abuse-ch.txt
```

The agent loads every feed at startup and logs the indicator count
(`threat intel loaded indicators=… feeds=…`). Indexing is exact-match maps for
IPs, domains and hashes plus a linear scan of CIDR ranges, so matching adds
negligible per-event cost.

## What a hit produces

Each matched indicator becomes a **high-severity alert** (`RuleID` `INTEL-IP`,
`INTEL-DOMAIN` or `INTEL-HASH`, risk score 60). Network indicators are tagged as
ATT&CK **T1071 — Application Layer Protocol** (command-and-control); a hash hit
carries no technique because it is identity, not behaviour. The alert flows
through correlation, response and outputs exactly like a rule match, so an IOC
hit can contribute to an incident and — when `response.mode` permits — drive an
nftables block or quarantine.

## Keeping feeds fresh

ARGUS loads feeds at startup and does not poll them; refreshing is intentionally
left to whatever you already trust to deliver files — a cron job pulling from a
provider, your config-management tool, or a future control-plane push. After
updating the files, restart the agent to pick up the new indicators.
