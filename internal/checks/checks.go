// Package checks runs the standard quality and security tool suite
// against a project and reduces each tool's output to a short list of
// issues, so the audit report shows only problems, never tool noise.
package checks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// maxIssuesPerTool caps how many lines one tool may contribute for one
// project so a messy repo cannot drown the report.
const maxIssuesPerTool = 10

// Issue is one problem reported by one tool. Security marks findings from
// the security scanners (gosec, govulncheck), which rank above ordinary
// lint and test issues.
type Issue struct {
	Tool     string `json:"tool"`
	Detail   string `json:"detail"`
	Security bool   `json:"security,omitempty"`
}

// Tool describes one external check: the command to run and how to turn
// its output into issues. When Resolve is set it computes the argv for a
// specific project directory; returning no argv skips the tool for that
// project with the returned note.
type Tool struct {
	Name    string
	Args    []string
	Resolve func(dir string) (args []string, note string)
	Parse   func(dir string, stdout, stderr []byte, exitCode int) []Issue
}

// DefaultTools returns the standard check suite: gofmt (as -l, so the
// audit never rewrites files), go vet, go fix (as -diff, reported as a
// summary and likewise never applied), staticcheck, errcheck, revive,
// gosec, govulncheck, and go test with the race detector. Coverage
// artifacts are not collected.
func DefaultTools() []Tool {
	return []Tool{
		{Name: "gofmt", Args: []string{"gofmt", "-l", "."}, Parse: parseGofmt},
		{Name: "vet", Args: []string{"go", "vet", "./..."}, Parse: lineParser("vet", false)},
		{Name: "gofix", Resolve: gofixArgs, Parse: parseGofix},
		{Name: "staticcheck", Args: []string{"staticcheck", "./..."}, Parse: lineParser("staticcheck", false)},
		{Name: "errcheck", Args: []string{"errcheck", "./..."}, Parse: lineParser("errcheck", false)},
		// revive exits 0 even when it prints warnings, so its output is
		// parsed regardless of exit code.
		{Name: "revive", Resolve: reviveArgs, Parse: lineParser("revive", true)},
		{Name: "gosec", Args: []string{"gosec", "-quiet", "-fmt=json", "./..."}, Parse: parseGosec},
		{Name: "govulncheck", Args: []string{"govulncheck", "-json", "./..."}, Parse: parseGovulncheck},
		{Name: "test", Args: []string{"go", "test", "./...", "-race", "-vet=all", "-shuffle=on", "-count=1", "-timeout=30s"}, Parse: parseGoTest},
	}
}

// gofixSupportsDiff reports whether the installed go command has the
// analysis-based `go fix -diff` mode (Go 1.26+). Without -diff, go fix
// rewrites source files — something the audit must never do — so older
// toolchains skip the check entirely. Toolchain auto-switching only ever
// selects a version at least as new as the installed one, so this is
// safe to cache across projects.
var gofixSupportsDiff = sync.OnceValue(func() bool {
	out, err := exec.Command("go", "help", "fix").CombinedOutput()
	return err == nil && bytes.Contains(out, []byte("-diff"))
})

func gofixArgs(string) ([]string, string) {
	if !gofixSupportsDiff() {
		return nil, "go fix skipped: this toolchain has no -diff mode (Go 1.26+); the audit never applies fixes"
	}
	return []string{"go", "fix", "-diff", "./..."}, ""
}

// reviveArgs prefers a revive.toml committed in the scanned project, then
// the user's ~/.revive.toml; with neither, revive is skipped for that
// project.
func reviveArgs(dir string) ([]string, string) {
	if local := filepath.Join(dir, "revive.toml"); fileExists(local) {
		return []string{"revive", "-config", local, "./..."}, ""
	}
	if home, err := os.UserHomeDir(); err == nil {
		if cfg := filepath.Join(home, ".revive.toml"); fileExists(cfg) {
			return []string{"revive", "-config", cfg, "./..."}, ""
		}
	}
	return nil, "revive skipped: no revive.toml in project or home"
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Run executes each tool in dir, returning the trimmed issue list plus
// notes about anything skipped. Packages that do not build on this
// platform (e.g. Windows-only code audited on Linux) are left out of the
// package-pattern tools and reported in a note, so the rest of the module
// is still checked.
func Run(ctx context.Context, dir string, tools []Tool) ([]Issue, []string) {
	pkgs, broken := listPackages(ctx, dir)
	if len(pkgs) == 0 && len(broken) == 0 {
		return nil, []string{"no Go packages; code checks skipped"}
	}
	var notes []string
	if len(broken) > 0 {
		notes = append(notes, fmt.Sprintf("%d of %d packages do not build on this platform; skipped: %s",
			len(broken), len(broken)+len(pkgs), strings.Join(broken, ", ")))
	}
	if len(pkgs) == 0 {
		return nil, append(notes, "no packages build on this platform; code checks skipped")
	}
	var issues []Issue
	for _, tool := range tools {
		args, note := resolveTool(dir, tool, pkgs, len(broken) > 0)
		if len(args) == 0 {
			if note != "" {
				notes = append(notes, note)
			}
			continue
		}
		tool.Args = args
		issues = append(issues, capIssues(runTool(ctx, dir, tool), tool.Name)...)
	}
	return issues, notes
}

// resolveTool finalizes a tool's argv for dir. Empty args means the tool
// is skipped, with note saying why (an empty note means the Resolve hook
// declined silently).
func resolveTool(dir string, tool Tool, pkgs []string, expand bool) (args []string, note string) {
	args = tool.Args
	if tool.Resolve != nil {
		args, note = tool.Resolve(dir)
		if len(args) == 0 {
			return nil, note
		}
	}
	if _, err := exec.LookPath(args[0]); err != nil {
		return nil, tool.Name + " not installed; skipped"
	}
	if expand {
		args = expandPattern(args, pkgs)
	}
	return args, ""
}

// expandPattern swaps the ./... pattern in a tool's argv for the explicit
// list of buildable packages, so tools never trip over packages that
// cannot compile on this platform. Tools without the pattern (gofmt works
// on files, not packages) are left alone.
func expandPattern(args, pkgs []string) []string {
	var out []string
	for _, arg := range args {
		if arg == "./..." {
			out = append(out, pkgs...)
			continue
		}
		out = append(out, arg)
	}
	return out
}

func runTool(ctx context.Context, dir string, tool Tool) []Issue {
	cmd := exec.CommandContext(ctx, tool.Args[0], tool.Args[1:]...) // #nosec G204 -- argv comes from the fixed tool table above
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return []Issue{{Tool: tool.Name, Detail: "could not run: " + err.Error()}}
		}
		exitCode = exitErr.ExitCode()
	}
	return tool.Parse(dir, stdout.Bytes(), stderr.Bytes(), exitCode)
}

// listPackages splits the project's packages into those that compile on
// this platform (pkgs) and those that cannot (broken), such as
// Windows-only code audited on Linux. Both lists empty means a
// module-only directory (e.g. a Hugo theme with a bare go.mod) with
// nothing for the code checks to run on.
//
// -export forces a real compile into the build cache (nothing is written
// to the project), so this catches type errors like Windows-only syscall
// fields, which a plain load would miss: Export stays empty for any
// package that fails to build. -e keeps the exit code 0 so one broken
// package cannot hide the rest.
func listPackages(ctx context.Context, dir string) (pkgs, broken []string) {
	cmd := exec.CommandContext(ctx, "go", "list", "-e", "-export", "-f", "{{.ImportPath}} {{if .Export}}ok{{else}}broken{{end}}", "./...")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if fields[1] == "broken" {
			broken = append(broken, fields[0])
		} else {
			pkgs = append(pkgs, fields[0])
		}
	}
	return pkgs, broken
}

func capIssues(issues []Issue, tool string) []Issue {
	if len(issues) <= maxIssuesPerTool {
		return issues
	}
	kept := append([]Issue{}, issues[:maxIssuesPerTool]...)
	return append(kept, Issue{
		Tool:     tool,
		Detail:   fmt.Sprintf("(+%d more %s findings)", len(issues)-maxIssuesPerTool, tool),
		Security: issues[0].Security,
	})
}

// outputLines merges and splits both output streams into trimmed lines.
func outputLines(stdout, stderr []byte) []string {
	var lines []string
	for _, raw := range [][]byte{stdout, stderr} {
		for _, line := range strings.Split(string(raw), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				lines = append(lines, line)
			}
		}
	}
	return lines
}

func firstNonEmptyLine(streams ...[]byte) string {
	for _, s := range streams {
		if lines := outputLines(s, nil); len(lines) > 0 {
			return lines[0]
		}
	}
	return "failed with no output"
}

// keepDiagnostic filters out compile-progress and package-header lines,
// leaving the file:line diagnostics the user needs to see.
func keepDiagnostic(line string) bool {
	return line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "go: downloading")
}

// lineParser builds a parser for tools that print one diagnostic per
// line. When evenOnSuccess is false, a zero exit code means no issues.
func lineParser(tool string, evenOnSuccess bool) func(string, []byte, []byte, int) []Issue {
	return func(_ string, stdout, stderr []byte, exitCode int) []Issue {
		if exitCode == 0 && !evenOnSuccess {
			return nil
		}
		var issues []Issue
		for _, line := range outputLines(stdout, stderr) {
			if keepDiagnostic(line) {
				issues = append(issues, Issue{Tool: tool, Detail: line})
			}
		}
		if len(issues) == 0 && exitCode != 0 {
			issues = append(issues, Issue{Tool: tool, Detail: firstNonEmptyLine(stderr, stdout)})
		}
		return issues
	}
}

// parseGofmt turns `gofmt -l .` output (one unformatted file per line)
// into issues, skipping vendored, testdata, and hidden paths.
func parseGofmt(_ string, stdout, _ []byte, _ int) []Issue {
	var issues []Issue
	for _, line := range outputLines(stdout, nil) {
		if skipPath(line) {
			continue
		}
		issues = append(issues, Issue{Tool: "gofmt", Detail: "file needs gofmt: " + line})
	}
	return issues
}

// parseGofix reduces `go fix -diff` output — a patch of suggested
// modernizations that is only ever printed, never applied — to a single
// summary line, so available fixes are visible without a wall of diff
// hunks drowning the real findings. Exit 0 means nothing to fix; a
// non-zero exit with no diff headers is a real failure (e.g. the module
// does not build), reported as-is.
func parseGofix(dir string, stdout, stderr []byte, exitCode int) []Issue {
	if exitCode == 0 {
		return nil
	}
	seen := map[string]bool{}
	sawDiff := false
	for _, line := range outputLines(stdout, nil) {
		name, ok := strings.CutPrefix(line, "--- ")
		if !ok || !strings.HasSuffix(name, " (old)") {
			continue
		}
		sawDiff = true
		name = strings.TrimSuffix(name, " (old)")
		if abs, err := filepath.Abs(dir); err == nil {
			if rel, err := filepath.Rel(abs, name); err == nil {
				name = rel
			}
		}
		if !skipPath(name) {
			seen[name] = true
		}
	}
	if len(seen) == 0 {
		if sawDiff {
			return nil // every suggested fix was in vendored or generated paths
		}
		return []Issue{{Tool: "gofix", Detail: firstNonEmptyLine(stderr, stdout)}}
	}
	return []Issue{{Tool: "gofix", Detail: fmt.Sprintf("modernizations available in %d file(s) — preview with 'go fix -diff ./...' (never auto-applied)", len(seen))}}
}

func skipPath(p string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == "vendor" || seg == "testdata" {
			return true
		}
		if seg != "." && strings.HasPrefix(seg, ".") {
			return true
		}
	}
	return false
}

// parseGoTest keeps only failure lines from `go test` output.
func parseGoTest(_ string, stdout, stderr []byte, exitCode int) []Issue {
	if exitCode == 0 {
		return nil
	}
	var issues []Issue
	for _, line := range outputLines(stdout, stderr) {
		if line == "FAIL" {
			continue
		}
		if strings.HasPrefix(line, "--- FAIL") || strings.HasPrefix(line, "FAIL") ||
			strings.Contains(line, "[build failed]") || strings.Contains(line, "DATA RACE") {
			issues = append(issues, Issue{Tool: "test", Detail: line})
		}
	}
	if len(issues) == 0 {
		issues = append(issues, Issue{Tool: "test", Detail: firstNonEmptyLine(stderr, stdout)})
	}
	return issues
}
