package checks

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// tidyTimeout bounds the tidy check: `go mod tidy` may need the network
// to load the module graph, and a dead proxy must not hang the audit.
const tidyTimeout = 2 * time.Minute

// Tidy reports whether `go mod tidy` would change the project, using the
// go tool's -diff mode (Go 1.23+), which only prints changes and never
// writes, so the audit stays read-only. Drift is a warning: an untidy
// go.mod means the audited dependency set no longer matches what the
// code imports. When the check cannot run at all (no network to load the
// module graph, an older toolchain without -diff) it is skipped with a
// note, never a finding.
func Tidy(ctx context.Context, dir string) ([]Issue, []string) {
	ctx, cancel := context.WithTimeout(ctx, tidyTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "mod", "tidy", "-diff")
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return nil, nil
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return nil, []string{"tidy check skipped: " + err.Error()}
	}
	return classifyTidy(stdout.Bytes(), stderr.Bytes())
}

// classifyTidy splits a non-zero `go mod tidy -diff` exit into its two
// meanings: a printed diff is drift, anything else is a tool failure.
func classifyTidy(stdout, stderr []byte) ([]Issue, []string) {
	if !hasDiffHeader(stdout) {
		return nil, []string{"tidy check skipped: " + firstNonEmptyLine(stderr, stdout)}
	}
	return []Issue{{
		Tool:  "tidy",
		Level: LevelWarning,
		Detail: "go.mod/go.sum are not tidy, so the audited dependency set may not match the imports; " +
			"run 'go mod tidy' (then 'go mod vendor' or 'go work vendor' if vendored)",
	}}, nil
}

// hasDiffHeader reports whether the output contains a unified diff
// header line, the shape `go mod tidy -diff` prints for each changed
// file.
func hasDiffHeader(stdout []byte) bool {
	for _, line := range strings.Split(string(stdout), "\n") {
		if strings.HasPrefix(line, "--- ") {
			return true
		}
	}
	return false
}
