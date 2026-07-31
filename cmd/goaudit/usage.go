package main

import (
	"flag"
	"io"
)

// usageHeader and usageFooter wrap the flag list to form the full help
// text, shown by `goaudit help`, `-help`, `--help`, or any flag error.
const usageHeader = `goaudit — audit Go projects for malicious packages, typosquats,
known vulnerabilities, and code quality.

Usage:

  goaudit [flags]
  goaudit help

With no flags, goaudit audits the project in the current directory.
Point --path at a directory without a go.mod (or add --recursive) to
discover and audit every Go project beneath it.

Every run prints a text report to stdout and writes a machine-readable
goaudit-report.json into the scanned directory. The text report shows at
most 10 lines per tool and sums the rest into one "+N more" line; the
counts in the result line always cover every finding. Use --cli to
print every line, or read the JSON report — it is never capped.

Flags:

`

const usageFooter = `
Report levels:

  FLAGGED   a known-malicious package
  SECURITY  gosec, govulncheck, or a dependency that gained a
            high-risk capability since its baseline
  WARNING   a typosquat suspect, or a defect with a definite fix:
            vet, staticcheck's SA checks, errcheck, gofmt, a failing
            test, an untidy go.mod (checked with "go mod tidy -diff",
            never applied)
  ISSUE     advice to weigh: revive, available modernizations, and
            staticcheck's style and simplification checks

Exit codes:

  0  clean
  1  known-malicious package found
  2  security findings and warnings — always; issues and projects that
     could not be scanned too when --fail-on-warn is set
  3  goaudit itself could not run (bad flags, no projects found)

Environment:

  GOAUDIT_SKIP_CHECKS   skip checks by name, comma-separated (for
                        example "tidy" or "test,capslock"); any
                        unknown value skips the whole check suite
  GOAUDIT_FEED_URL      override the Socket PolinRider feed URL;
                        the value "off" disables that feed
  GOAUDIT_OSV_FEED_URL  override the OSV malicious-package feed URL;
                        the value "off" disables that feed
  GOAUDIT_DATA_DIR      relocate the feed/data directory

Examples:

  goaudit                            audit the current project
  goaudit --path ~/projects          audit every Go project under ~/projects
  goaudit --path . --fail-on-warn    CI gate: any finding at all fails
  goaudit --cli                      show every finding, no per-tool cap
  goaudit --update-baselines         accept current capslock capabilities

Full documentation: https://github.com/thesimpledev/goaudit
`

// printUsage writes the complete help text: header, the flag list from
// fs, and the footer.
func printUsage(w io.Writer, fs *flag.FlagSet) {
	printf(w, "%s", usageHeader)
	fs.PrintDefaults()
	printf(w, "%s", usageFooter)
}
