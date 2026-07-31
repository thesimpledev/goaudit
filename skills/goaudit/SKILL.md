---
name: goaudit
description: Audit Go projects for malicious packages, typosquats, known vulnerabilities, capability changes, and code quality using the goaudit CLI. Use when asked to audit, security-scan, vet, or check the health of a Go project or a directory of Go projects; before committing, releasing, or adding a new Go dependency; when investigating whether a dependency is malicious or a typosquat; or when a goaudit run needs to be interpreted, gated in CI, or its baselines updated.
---

# goaudit

`goaudit` audits Go projects for malicious packages, typosquats, known
vulnerabilities, dependency capability changes, and code quality. It
prints a text report and always writes a machine-readable
`goaudit-report.json` into the scanned directory.

Source: https://github.com/thesimpledev/goaudit

## Running it

```sh
goaudit                      # audit the project in the current directory
goaudit --path <dir>         # audit that project
goaudit --path <dir> --cli   # same, but print every finding
goaudit help                 # full built-in reference
```

If `<dir>` has no `go.mod`, or `--recursive` is passed, every Go project
underneath it is discovered and audited separately.

Vendored projects and workspace-vendored monorepos (a `go.work` with a
shared `vendor/` directory) are audited from `vendor/modules.txt`, with
no network needed for the module list. In such a monorepo, a dependency
finding repeats under every member project, because the vendor directory
is shared: fixing it once fixes them all.

Check that `goaudit` is on `PATH` before relying on it. If it is
missing:

```sh
go install github.com/thesimpledev/goaudit/cmd/goaudit@latest
```

goaudit itself has no dependencies, but several checks come from
optional analyzers. Missing ones are noted and skipped, so a bare
install still audits dependencies and runs `gofmt`, `go vet`,
`go fix -diff`, and `go test -race`. For the full suite:

```sh
go install honnef.co/go/tools/cmd/staticcheck@latest
go install github.com/kisielk/errcheck@latest
go install github.com/mgechev/revive@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/google/capslock/cmd/capslock@latest
```

## Reading the output

Findings come at four levels:

| Level | Meaning | Exit code |
|---|---|---|
| `FLAGGED` | known-malicious package (feed or local IOC match) | 1, always |
| `SECURITY` | gosec, govulncheck, or a gained high-risk capability | 2, always |
| `WARNING` | typosquat heuristic; vet, staticcheck's `SA` checks, errcheck, gofmt, failing tests, capability report, untidy go.mod | 2, always |
| `ISSUE` | revive, staticcheck's `S1`/`ST1`/`QF`/`U` checks, available modernizations from `go fix` | 2 only with `--fail-on-warn` |

A `WARNING` is a defect with a definite fix, and fails the run on its
own; an `ISSUE` is advice to weigh, and fails only with
`--fail-on-warn`, which also covers projects that could not be scanned.
The `result:` line and the JSON `warnings` count add the two kinds of
warning together — read each entry's own `level` in the JSON `checks`
array, or the label on each text line, to tell a typosquat suspect from
a lint finding.

Exit 0 is clean. Exit 3 means goaudit itself could not run (bad flags,
no projects found), which is a tooling problem, not a finding. A single
project that cannot be scanned shows up as an `ERROR` section and does
not kill the run unless `--fail-on-warn` is set.

**Parse the JSON, not the text.** The text report caps each tool at 10
lines per project and sums the rest into a `+N more` line. The counts on
the `result:` line cover everything, and `goaudit-report.json` is never
capped. Use `--cli` when a human wants to read every line in the
terminal.

`goaudit-report.json` should be gitignored, not committed.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--path` | `.` | A project directory, or a parent directory of many projects |
| `--recursive` | false | Scan every Go project under `--path` (automatic when `--path` has no `go.mod`) |
| `--local-ioc` | (none) | Extra IOC file applied to every scanned project |
| `--fail-on-warn` | false | Issues and unscannable projects also fail the run (warnings always do) |
| `--verbose` | false | Include clean modules in the report |
| `--cli` | false | Show every finding in the text report |
| `--update-baselines` | false | Re-record capslock baselines, accepting current capabilities |

## Environment variables

- `GOAUDIT_SKIP_CHECKS` skips checks by name, comma-separated
  (`tidy`, `capslock`, or `test,capslock`). Any other non-empty value
  skips the whole check suite. Use this when a run is too slow,
  especially the first capslock analysis of a large tree.
- `GOAUDIT_FEED_URL` and `GOAUDIT_OSV_FEED_URL` override the threat feed
  endpoints; the value `off` disables that feed.
- `GOAUDIT_DATA_DIR` relocates the shared data directory (Linux default
  `~/.local/share/goaudit`). Persist that directory between ephemeral CI
  runs so the ~10 MB OSV export is not re-downloaded every time.

## Capability baselines

With capslock installed, the first run on a project writes
`.goaudit-capslock.json`, a baseline of what every dependency is *able*
to do. **Commit that file.** It is what makes the capability diff
meaningful across machines and in code review.

Later runs report only capabilities gained since the baseline. A gained
high-risk capability (`EXEC`, `NETWORK`, `SYSTEM_CALLS`,
`ARBITRARY_EXECUTION`, `CGO`, `UNSAFE_POINTER`) is a `SECURITY` finding
and fails the run; other gains are `WARNING`s. A reported gain repeats
every run until it is accepted with `--update-baselines`. Do not run
`--update-baselines` to make a finding go away without first
establishing why the capability appeared.

While `go.sum` is unchanged, capslock is skipped entirely, so
steady-state runs are cheap.

## False positives

A typosquat `WARNING` on a module that is genuinely fine, or any other
false positive, is suppressed with an `allow` entry in a
`.goaudit-ioc.json` next to the project's `go.mod`:

```json
{
  "allow": ["github.com/gofrs/uuid"]
}
```

The same file can add local IOC entries. In multi-project mode, a
`.goaudit-ioc.json` at the scan root applies to every project and each
project's own file layers on top.

## CI gating

```sh
goaudit --path . --fail-on-warn
```

That makes any finding at all fail the gate, down to revive's advice
and a project that could not be scanned. Without `--fail-on-warn`,
malicious packages, security findings, and warnings fail.

## What it never does

goaudit does not modify the tree it scans, apart from writing
`goaudit-report.json` and the capslock baseline. Formatting is checked
with `gofmt -l`, modernizations with `go fix -diff`, and go.mod
tidiness with `go mod tidy -diff`; none of them is ever applied. Fixing
what it reports is a separate, deliberate step.
