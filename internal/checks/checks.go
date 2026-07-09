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
// audit never rewrites files), go vet, staticcheck, errcheck, revive,
// gosec, govulncheck, and go test with the race detector. Coverage
// artifacts are not collected.
func DefaultTools() []Tool {
	return []Tool{
		{Name: "gofmt", Args: []string{"gofmt", "-l", "."}, Parse: parseGofmt},
		{Name: "vet", Args: []string{"go", "vet", "./..."}, Parse: lineParser("vet", false)},
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
// notes about anything skipped.
func Run(ctx context.Context, dir string, tools []Tool) ([]Issue, []string) {
	if !hasPackages(ctx, dir) {
		return nil, []string{"no Go packages; code checks skipped"}
	}
	var issues []Issue
	var notes []string
	for _, tool := range tools {
		if tool.Resolve != nil {
			args, note := tool.Resolve(dir)
			if len(args) == 0 {
				if note != "" {
					notes = append(notes, note)
				}
				continue
			}
			tool.Args = args
		}
		if _, err := exec.LookPath(tool.Args[0]); err != nil {
			notes = append(notes, tool.Name+" not installed; skipped")
			continue
		}
		issues = append(issues, capIssues(runTool(ctx, dir, tool), tool.Name)...)
	}
	return issues, notes
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

// hasPackages reports whether the project contains any Go packages;
// module-only directories (e.g. a Hugo theme with a bare go.mod) have
// nothing for the code checks to run on.
func hasPackages(ctx context.Context, dir string) bool {
	cmd := exec.CommandContext(ctx, "go", "list", "./...")
	cmd.Dir = dir
	out, err := cmd.Output()
	return err == nil && len(bytes.TrimSpace(out)) > 0
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
