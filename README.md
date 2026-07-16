# goaudit

[![CI](https://github.com/thesimpledev/goaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/thesimpledev/goaudit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

One command that audits every Go project it finds — for malicious
packages, typosquats, known vulnerabilities, and code quality — and
tells you only what's wrong.

```sh
goaudit --path ~/projects
```

```
goaudit multi-project audit: /home/you/projects
projects found: 93 | shared IOC entries: 81
note: Socket PolinRider feed cache fresh (2h0m0s old)
note: OSV malicious-package feed cache fresh (2h0m0s old)

── you/api-server (/home/you/projects/api-server)
   FLAGGED  github.com/evil/pkg@v1.2.3
            exact match in IOC list
   SECURITY [govulncheck] GO-2026-5004: SQL injection in github.com/jackc/pgx (v5.8.0, fixed in v5.9.2)
   ISSUE    [errcheck] cmd/server/main.go:29:16:  defer ln.Close()
   result: 1 flagged, 0 warning(s), 1 security finding(s), 1 issue(s), 41 clean

── you/cli-tool (/home/you/projects/cli-tool)
   result: all 12 modules clean, all checks passed

overall: 93 projects, 1437 modules checked | 1 flagged, 0 warning(s), 1 security finding(s), 1 issue(s), 0 failed
```

Standard library only — no dependencies. No configuration: the threat
feeds (OpenSSF malicious-packages via OSV.dev, plus Socket's PolinRider
campaign list) are built in and kept fresh automatically.

> **What it writes:** every run saves a machine-readable
> `goaudit-report.json` into the scanned directory (the path is printed
> at the end). Consider adding that filename to your global gitignore.
> With capslock installed, the first run also records a
> `.goaudit-capslock.json` capability baseline per project — that one
> you should **commit** (see
> [capability baselines](#capability-baselines-capslock)). Nothing else
> in your tree is ever modified — formatting is checked with `gofmt -l`
> and modernizations with `go fix -diff`, never rewritten or applied.

## Install

```sh
go install github.com/thesimpledev/goaudit/cmd/goaudit@latest
```

That bare install already gives you the dependency audit (malicious
packages + typosquats) plus the checks that ship with Go itself
(`gofmt`, `go vet`, `go fix -diff`, `go test -race`). For the full
suite, install the
optional analyzers — any that are missing are simply noted and
skipped:

```sh
go install honnef.co/go/tools/cmd/staticcheck@latest
go install github.com/kisielk/errcheck@latest
go install github.com/mgechev/revive@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/google/capslock/cmd/capslock@latest
```

## What it checks

**1. Dependency audit** — every module in `go list -m all` (including
`replace` targets that point at other modules) is compared against a
malicious-package feed and typosquat heuristics:

- **FLAGGED — exact IOC match.** The module path appears in the threat
  feed or a local IOC file and the version matches (an entry with no
  versions flags every version). Also warns when a module has known-bad
  versions but you're on a different one.
- **WARNING — typosquat.** The path is within a small edit distance of
  a popular Go module, or reuses a popular module's name under an owner
  that imitates the real one (`stretchr-dev/testify`). See
  [how typosquat detection works](#how-typosquat-detection-works).

**2. Check suite** — each project is also run through the standard Go
quality/security pipeline, with all tool noise stripped:

| Tool | Surfaces as |
|---|---|
| `gosec` | `SECURITY` — each finding with rule ID and severity |
| `govulncheck` | `SECURITY` — each known CVE whose vulnerable code is actually reached |
| `capslock` | `SECURITY` — a dependency *gained* a high-risk capability since your baseline; `ISSUE` for the rest (see [capability baselines](#capability-baselines-capslock)) |
| `gofmt -l` | `ISSUE` — files needing formatting (list only) |
| `go fix -diff` | `ISSUE` — one summary line counting files with modernizations available (Go 1.26+; suggestions are never applied) |
| `go vet`, `staticcheck`, `errcheck`, `revive` | `ISSUE` — one line per diagnostic |
| `go test -race -vet=all -shuffle=on -count=1 -timeout=30s` | `ISSUE` — failing tests, build failures, data races |

Output is capped at 10 lines per tool per project (with a `+N more`
marker). A clean project collapses to a single line. revive uses a
`revive.toml` found in the scanned project if there is one, then
`~/.revive.toml`, otherwise it's skipped.

`GOAUDIT_SKIP_CHECKS` skips checks by name (`capslock` or
`test,capslock`); any other non-empty value — like the traditional `1` —
skips the whole suite.

## Severity and exit codes

| Level | Meaning | Exit code |
|---|---|---|
| `FLAGGED` | known-malicious package | 1, always |
| `SECURITY` | gosec / govulncheck finding | 2, always |
| `WARNING` | typosquat heuristics | 2 only with `--fail-on-warn` |
| `ISSUE` | lint, formatting, failing tests | 2 only with `--fail-on-warn` |

Exit 3 means the tool itself couldn't run (bad flags, no projects
found). A single project that can't be scanned (broken `go.mod`)
appears as an `ERROR` section but never kills the run, and feed
download problems degrade to a warning with the stale cache — never a
failure. Transient network errors are retried three times with backoff.

For CI or a pre-commit hook:

```sh
goaudit --path . --fail-on-warn   # anything at all fails the gate
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--path` | `.` | A project directory, or a parent directory of many projects |
| `--recursive` | false | Scan every Go project under `--path` (automatic when `--path` has no `go.mod`) |
| `--local-ioc` | (none) | Extra IOC file applied to every scanned project |
| `--fail-on-warn` | false | Warnings and issues also fail the run |
| `--verbose` | false | Include clean modules in the report |
| `--update-baselines` | false | Re-record each project's capslock capability baseline, accepting its current capabilities |

Interactive runs show a live progress line on stderr
(`auditing [12/93] owner/repo`); it disappears automatically when
output is piped or the `CI` environment variable is set.

## Threat feeds

Two feeds are built in, each loading and failing independently:

- **OpenSSF malicious-packages** — the community database of confirmed
  malicious open-source packages (the same data `osv-scanner` uses),
  fetched as OSV.dev's Go ecosystem export:

      https://storage.googleapis.com/osv-vulnerabilities/Go/all.zip

  Only the `MAL-` records are used; the vulnerability records in the
  same archive are skipped without being decompressed — govulncheck
  covers those. Credit to the [OpenSSF malicious-packages
  project](https://github.com/ossf/malicious-packages) and OSV.dev.

- **Socket PolinRider** — [Socket](https://socket.dev)'s public feed
  for the **PolinRider** supply chain attack campaign, kept alongside
  the OpenSSF data because campaign feeds can list packages days before
  they pass review into the general database:

      https://socket.dev/api/public/supply-chain-attacks/polinrider/packages.csv

  Full credit to the Socket research team.

Feed data is stored once per user in the platform's standard program
data directory — Linux `~/.local/share/goaudit` (or `$XDG_DATA_HOME`),
Windows `%LocalAppData%\goaudit`, macOS
`~/Library/Application Support/goaudit` — and shared by every project
you scan. Feeds re-download only when the stored copy is older than
24 hours, using ETags so an unchanged feed costs a 304. In ephemeral CI
runners, persist that directory between runs to avoid re-downloading
the ~10 MB OSV export each time.

`GOAUDIT_FEED_URL` and `GOAUDIT_OSV_FEED_URL` override the endpoints;
the value `off` disables that feed. `GOAUDIT_DATA_DIR` relocates the
data directory (`GOAUDIT_CACHE_DIR` is the deprecated old name and
still works). Upgrading from a version that cached under
`~/.cache/goaudit`: the old cache is simply abandoned and the feeds
re-download once into the new location.

## Multi-project mode

Point `--path` at a directory without a `go.mod` and goaudit discovers
every project beneath it (skipping hidden directories, `vendor`,
`testdata`, and `node_modules`; nested modules in multi-module repos
are audited separately). Use `--recursive` to force discovery at a
monorepo root that has its own `go.mod`. Projects are scanned
concurrently. Project names come from the module path with the host
stripped (`github.com/owner/repo` → `owner/repo`), falling back to the
folder name.

The feeds and `--local-ioc` file load once for the whole run; a
`.goaudit-ioc.json` at the scan root applies to every project (one
shared allowlist), and each project's own `.goaudit-ioc.json` layers on
top for that project only.

## Local IOC files

Add your own entries and allowlist on top of the feeds:

```json
{
  "entries": [
    {
      "module": "github.com/example-attacker/totally-legit-logging",
      "versions": ["v1.0.2"],
      "campaign": "PolinRider",
      "reason": "installs a credential stealer from an init() function"
    }
  ],
  "allow": ["github.com/gofrs/uuid"]
}
```

`allow` suppresses all findings for a module — the escape hatch for
any false positive. An entry with no `versions` flags every version.
CSV works too (header row; `module`/`package` or Socket-style
`namespace` + `name` columns; several versions per cell split on `|`
or `;`). See `examples/ioc.example.json`.

## Capability baselines (Capslock)

With [Capslock](https://github.com/google/capslock) installed, goaudit
watches what your dependencies are *able to do* — run programs, open
network connections, make raw system calls — and alerts when that
changes. This catches the class of attack no known-malware feed can: a
package you already trust ships an update that quietly starts phoning
home.

- **First run** on a project records `.goaudit-capslock.json`, a
  baseline of every package's capabilities, and lists the high-risk
  ones already present (`EXEC`, `NETWORK`, `SYSTEM_CALLS`,
  `ARBITRARY_EXECUTION`, `CGO`, `UNSAFE_POINTER`) as `ISSUE`s — an
  inventory, not an incident.
- **Later runs** report only capabilities *gained* since the baseline.
  A gained high-risk capability is a `SECURITY` finding and fails the
  run (exit 2); other gains are `ISSUE`s. The finding names the call
  responsible: `example.com/pkg gained NETWORK (via net/http.Get) since
  baseline`.
- **While `go.sum` is unchanged, capslock is skipped entirely** — the
  analysis is expensive (whole-program), so steady-state runs cost
  nothing. When dependencies change but capabilities don't, the
  baseline refreshes itself silently.
- **To accept reported changes**, rerun with `--update-baselines` (or
  delete the baseline file). A reported gain repeats every run until
  you do — deliberately, like failing CI.

Commit the baseline file: that's what makes the diff meaningful across
machines and CI, and a pull request that changes it shows a reviewable
capability diff. The baseline records the platform it was built on
(`goos`/`goarch`) and replays it on later runs so results compare
apples to apples. The first analysis of a big multi-project tree is
slow (bounded at 5 minutes per project); skip it with
`GOAUDIT_SKIP_CHECKS=capslock` if you're in a hurry.

## How typosquat detection works

A corpus of ~140 popular Go module paths is embedded in the binary
(`internal/match/popular_modules.txt`). A dependency warns when:

- its normalized path is within a small Levenshtein distance of a
  corpus entry (`github.com/strechr/testify`), or
- it reuses a corpus entry's repo name **and** its owner name imitates
  the real owner — one containing the other, like
  `gorilla-io/websocket` or the historical `Sirupsen` case-swap.

Unrelated owners sharing a repo name (`coder/websocket` vs
`gorilla/websocket`) are *not* reported: that rule originally produced
20 false positives across 93 real projects and zero true positives, so
it was tightened until the same sweep produced none without losing any
real detections. Major-version suffixes (`/v2`, `.v2`) are normalized
first so `jwt/v4` never trips against `jwt/v5`. Modules that are
themselves in the corpus are always clean, and the `allow` list covers
anything else. PRs extending the corpus with widely-used modules are
welcome.

## Development

```sh
go build ./...
go test ./... -race -vet=all -shuffle=on -count=1
go run ./cmd/goaudit --path .     # the tool audits itself: full lint + security suite
```

CI (GitHub Actions) runs gofmt, vet, staticcheck, errcheck, revive
(with the committed `revive.toml`), gosec, govulncheck, the race-enabled
tests with coverage, and finally a self-audit.

## Limitations, honestly

- The typosquat corpus is a curated snapshot; a squat of a module not
  in it goes unnoticed.
- The feeds cover the OpenSSF malicious-packages database and the
  PolinRider campaign as published by Socket — malware unknown to both
  goes unnoticed until someone reports it.
- govulncheck findings depend on the Go toolchain version doing the
  scanning; an outdated local Go reports its own stdlib CVEs across
  every project (accurately).

## License

MIT — see [LICENSE](LICENSE).
