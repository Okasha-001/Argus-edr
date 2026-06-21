# YARA signature scanning

ARGUS can scan executed files against [YARA](https://virustotal.github.io/yara/)
signatures and raise an alert on a match. It ships a small, dependency-free
engine for a practical subset of the language, so signature scanning adds **no
cgo dependency on libyara** — the Go build still needs no C toolchain.

It is **off by default**. A standalone agent does no scanning until you enable it.

## How it works

```
exec event ──▶ enrich ──▶ YaraScanner.Scan(process.executable)
                              │  reads up to yara.max_bytes of the file
                              ▼
                         yara.matched (rule names)  ──▶ rule R-0073 ──▶ alert
```

The enrich stage scans the **binary that is executed** (`process.executable`),
not arbitrary files, so the bundled signatures target malicious *binaries*
(coin miners, reverse-shell tools, dropped ELFs, and the EICAR test file).
Interpreted scripts — a webshell run as `php shell.php` — are out of scope for
this path, because the executable is the interpreter, not the script.

## Enabling it

```yaml
yara:
  enabled: true
  rules_dir: /etc/argus/yara   # every *.yar file here is compiled at startup
  max_bytes: 16777216          # scan at most this many bytes per file (16 MiB)
```

Hits are exposed to the rule engine as `yara.matched` (a comma-joined list of
matching rule names). The shipped rule **R-0073** alerts on any match:

```yaml
- { field: yara.matched, op: exists }
```

You can also write narrower rules, e.g. `{ field: yara.matched, op: contains,
value: "CoinMiner" }`.

## Supported rule subset

The engine implements the parts of YARA that signature rules actually use:

- **Text strings** — `$a = "evil"`, with the `nocase` modifier
  (`ascii`/`wide`/`fullword` are accepted but inert).
- **Hex strings** — `$b = { 7F 45 4C 46 ?? 01 }`, where `??` is a full-byte
  wildcard.
- **Conditions** — string identifiers combined with `and` / `or` / `not` and
  parentheses, the literals `true`/`false`, and the quantifiers
  `all of them`, `any of them`, and `N of them`.

Anything outside the subset (counted sets like `2 of ($a*)`, `at`/`in` offsets,
modules, `filesize`, regular-expression strings) is a **compile error**, so a
rule can never silently match nothing. Bundled signatures live in
`rules/yara/default.yar`.

## Limitations

- Scans the executed binary only (see above); no on-write or on-read file
  scanning yet.
- `Scan` is plain substring/byte-pattern search (O(n·m)); fine for the bounded
  file slices the agent feeds it, not a high-throughput file server scanner.
- Single-nibble wildcards (`4?`) and regex strings are not supported.
