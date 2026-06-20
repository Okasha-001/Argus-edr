---
name: clean-code
description: The master clean-code reference for ARGUS. Use when writing, reviewing, or refactoring any Go or C in this repo — long functions, unclear names, swallowed errors, deep nesting, magic numbers, or before a PR.
metadata:
  source: Adapted from Robert C. Martin's "Clean Code" for a Go + eBPF codebase.
---

# Clean Code (ARGUS)

Code is read far more than it is written. Optimise for the next reader. These are
the principles every change is held to; the language-specific and domain skills
(`go-style`, `ebpf-sensors`, `detection-rules`) build on them.

## Names reveal intent

A name that needs a comment to be understood is the wrong name.

```go
// Bad
d := 30 * time.Second
for _, x := range rs { ... }

// Good
const correlationWindow = 30 * time.Second
for _, rule := range rules { ... }
```

- Booleans read as a question: `isShell`, `hasParent`, `enforce`.
- Collections are plural: `rules`, `alerts`, `sinks`.
- Constants are named, never magic: `defaultRingBufferBytes`, not `8388608`.
- Name length matches scope: `i` in a three-line loop is fine; a package-level
  value is not `max`.

## Functions do one thing

Keep them small (< 20 lines is the target). If you can extract a named function,
the original was doing more than one thing.

```go
// Good: each step is named; the top function reads like a sentence.
func (p *Pipeline) process(event *model.Event) {
    p.enrich(event)
    result := p.engine.Evaluate(event)
    p.respond(result.Alerts)
    p.emit(event, result)
}
```

Max 3 parameters. Beyond that, pass a struct (`pipeline.Params`,
`enrich.Options`). No boolean flag parameters that make a function do two things
— split it instead.

## Errors are handled deliberately

```go
// Bad: context lost, or error swallowed.
if err != nil { return err }
data, _ := os.ReadFile(path)

// Good: wrapped with what failed.
if err != nil {
    return fmt.Errorf("load spec %s: %w", path, err)
}
```

The only errors you may ignore are best-effort cleanup (`defer f.Close()`), and
the linter is configured to permit exactly that. Everywhere else: handle or
propagate with context.

## Comments explain WHY

The code already says what it does. A comment earns its place by explaining a
decision the code can't:

```go
// Stamp a stable start time on every event of a known process so its
// ProcessKey is consistent across event types, which correlation relies on.
```

Never commit commented-out code, change history, or comments that restate the
line below them. Delete obsolete comments the moment they stop being true.

## Structure

- **DRY** — one authoritative place for each piece of knowledge.
- **Guard clauses** over deep nesting; return early.
- **One abstraction level per function** — don't mix high-level orchestration
  with byte-twiddling in the same body.
- **Dead code is deleted**, not commented. Git remembers.

## Severity guide (for review)

| Level | Examples |
|-------|----------|
| Must fix | swallowed error, ABI mismatch, name that misleads, function doing 3+ things |
| Should fix | > 50-line function, > 3 params without a struct, magic number, deep nesting |
| Consider | 20–50 line function, comment that restates code, minor naming |

## The Boy-Scout rule

Leave each file a little cleaner than you found it — rename one unclear variable,
delete one dead line — but keep the cleanup proportional to the change you came
to make. Don't reformat a file you're adding one line to.
