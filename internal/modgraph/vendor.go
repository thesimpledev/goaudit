package modgraph

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// vendorFile returns the vendor/modules.txt that governs dir: the
// workspace copy when dir belongs to a Go workspace (the go tool only
// honors workspace-level vendoring there), otherwise the project's own,
// or "" when the build is not vendored.
func vendorFile(ctx context.Context, dir string) string {
	if root := workspaceRoot(ctx, dir); root != "" {
		if path := filepath.Join(root, "vendor", "modules.txt"); fileExists(path) {
			return path
		}
		return ""
	}
	if path := filepath.Join(dir, "vendor", "modules.txt"); fileExists(path) {
		return path
	}
	return ""
}

// workspaceRoot returns the directory of the go.work file governing dir,
// or "" when dir is not in a Go workspace. `go env GOWORK` honors both
// the GOWORK variable and the upward file search, so the answer matches
// what every later go command sees.
func workspaceRoot(ctx context.Context, dir string) string {
	cmd := exec.CommandContext(ctx, "go", "env", "GOWORK")
	cmd.Dir = dir
	out, err := cmd.Output()
	gowork := strings.TrimSpace(string(out))
	if err != nil || gowork == "" || gowork == "off" {
		return ""
	}
	return filepath.Dir(gowork)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// listVendored builds the module list for a vendored build: the main
// module from dir's go.mod followed by every module recorded in
// modulesTxt. That file lists exactly the modules whose code is in the
// build, it needs no network, and it is the only module source the go
// tool leaves usable under workspace vendoring.
func listVendored(modulesTxt, dir string) ([]Module, error) {
	main, err := mainModule(dir)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(modulesTxt) // #nosec G304 -- path is vendor/modules.txt inside the scanned project or its workspace
	if err != nil {
		return nil, err
	}
	return append([]Module{main}, parseModulesTxt(data)...), nil
}

// mainModule reads the module path out of dir's go.mod.
func mainModule(dir string) (Module, error) {
	path := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(path) // #nosec G304 -- path is go.mod inside the scanned project
	if err != nil {
		return Module{}, err
	}
	p := modulePath(data)
	if p == "" {
		return Module{}, fmt.Errorf("no module directive in %s", path)
	}
	return Module{Path: p, Main: true}, nil
}

// modulePath extracts the module path from go.mod contents.
func modulePath(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module")
		if !ok || (rest != "" && rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		if i := strings.Index(rest, "//"); i >= 0 {
			rest = rest[:i]
		}
		if p := strings.Trim(strings.TrimSpace(rest), `"`); p != "" {
			return p
		}
	}
	return ""
}

// parseModulesTxt reads the module records out of vendor/modules.txt.
// A `# path version` line opens a module (with an optional `=>
// replacement`), a following `## explicit` marker means a main module
// requires it directly, and unprefixed package lines are skipped.
func parseModulesTxt(data []byte) []Module {
	var mods []Module
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "# "); ok {
			if m, ok := parseModuleLine(rest); ok {
				mods = append(mods, m)
			}
			continue
		}
		if strings.HasPrefix(line, "##") && strings.Contains(line, "explicit") && len(mods) > 0 {
			mods[len(mods)-1].Indirect = false
		}
	}
	return mods
}

// parseModuleLine parses one `path [version] [=> path [version]]`
// module record. A replacement without a version is a filesystem
// replace, kept so the match engine can see and skip it.
func parseModuleLine(rest string) (Module, bool) {
	req, repl, replaced := strings.Cut(rest, "=>")
	fields := strings.Fields(req)
	if len(fields) == 0 {
		return Module{}, false
	}
	m := Module{Path: fields[0], Indirect: true}
	if len(fields) > 1 {
		m.Version = fields[1]
	}
	if rf := strings.Fields(repl); replaced && len(rf) > 0 {
		r := Module{Path: rf[0]}
		if len(rf) > 1 {
			r.Version = rf[1]
		}
		m.Replace = &r
	}
	return m, true
}
