// Package modgraph lists the module requirement graph of a Go project by
// shelling out to the go tool.
package modgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Module mirrors the fields of `go list -m -json` output that the audit
// needs.
type Module struct {
	Path     string
	Version  string
	Main     bool
	Indirect bool
	Replace  *Module
}

// listAttempts is how many times a transient network failure is retried.
const listAttempts = 3

// transientMarkers identify go tool failures caused by flaky DNS or
// network conditions. These are worth retrying: modules fetched before the
// failure stay in the local cache, so every attempt makes progress.
var transientMarkers = []string{
	"dial tcp",
	"i/o timeout",
	"connection reset",
	"connection refused",
	"server misbehaving",
	"TLS handshake timeout",
	"temporary failure",
}

// isTransient reports whether an error message looks like a temporary
// network problem rather than a broken project.
func isTransient(msg string) bool {
	for _, marker := range transientMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// List returns every module in the project's requirement graph, retrying
// transient network failures with a short backoff.
func List(ctx context.Context, dir string) ([]Module, error) {
	var lastErr error
	for attempt := 1; attempt <= listAttempts; attempt++ {
		mods, err := listGraph(ctx, dir)
		if err == nil {
			return mods, nil
		}
		if !isTransient(err.Error()) {
			return nil, err
		}
		lastErr = err
		if attempt < listAttempts {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
	}
	return nil, fmt.Errorf("%w (network failure persisted through %d attempts)", lastErr, listAttempts)
}

// listGraph runs `go list -m all` once, including the main module (marked
// Main). Vendored projects are listed with -mod=mod because the graph
// cannot be resolved from a vendor directory.
func listGraph(ctx context.Context, dir string) ([]Module, error) {
	dir = filepath.Clean(dir)
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		return nil, fmt.Errorf("no go.mod in %s: %w", dir, err)
	}

	var cmd *exec.Cmd
	if vendored(dir) {
		cmd = exec.CommandContext(ctx, "go", "list", "-mod=mod", "-m", "-json", "all")
	} else {
		cmd = exec.CommandContext(ctx, "go", "list", "-m", "-json", "all")
	}
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("go list -m all failed: %s", msg)
	}
	return parse(&stdout)
}

// vendored reports whether the project has a populated vendor directory.
func vendored(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "vendor", "modules.txt"))
	return err == nil
}

// parse decodes the stream of JSON objects that `go list -m -json` emits.
func parse(r io.Reader) ([]Module, error) {
	dec := json.NewDecoder(r)
	var mods []Module
	for {
		var m Module
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		mods = append(mods, m)
	}
	return mods, nil
}
