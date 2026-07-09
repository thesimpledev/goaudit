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
// cannot be resolved from a vendor directory; -mod=mod also lets the go
// tool rewrite go.mod and go.sum while resolving, so both files are
// snapshotted and put back — an audit must never modify the project it
// scans.
func listGraph(ctx context.Context, dir string) ([]Module, error) {
	dir = filepath.Clean(dir)
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		return nil, fmt.Errorf("no go.mod in %s: %w", dir, err)
	}

	var cmd *exec.Cmd
	if vendored(dir) {
		restore, err := preserve(filepath.Join(dir, "go.mod"), filepath.Join(dir, "go.sum"))
		if err != nil {
			return nil, err
		}
		defer restore()
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

// snapshot holds one file's contents from before the go tool ran, so any
// rewrite can be undone. existed false means the file was absent.
type snapshot struct {
	path    string
	data    []byte
	mode    os.FileMode
	existed bool
}

// preserve snapshots the named files and returns a function that puts the
// original contents back, undoing any rewrite the go tool made.
func preserve(paths ...string) (restore func(), err error) {
	var snaps []snapshot
	for _, path := range paths {
		snap, err := takeSnapshot(path)
		if err != nil {
			return nil, err
		}
		snaps = append(snaps, snap)
	}
	return func() {
		for _, snap := range snaps {
			snap.restore()
		}
	}, nil
}

func takeSnapshot(path string) (snapshot, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return snapshot{path: path}, nil
	}
	if err != nil {
		return snapshot{}, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is go.mod/go.sum inside the scanned project
	if err != nil {
		return snapshot{}, err
	}
	return snapshot{path: path, data: data, mode: info.Mode(), existed: true}, nil
}

// restore puts the snapshotted contents back; a file absent at snapshot
// time is deleted again if the tool created it. Failures are ignored
// because the graph result still stands.
func (s snapshot) restore() {
	if !s.existed {
		_ = os.Remove(s.path)
		return
	}
	if current, err := os.ReadFile(s.path); err == nil && bytes.Equal(current, s.data) { // #nosec G304 -- same path as above
		return
	}
	_ = os.WriteFile(s.path, s.data, s.mode) // #nosec G306 -- restoring the file's original mode
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
