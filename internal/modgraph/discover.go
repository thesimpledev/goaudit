package modgraph

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// skipDirs are directory names never descended into during discovery.
var skipDirs = map[string]struct{}{
	"vendor":       {},
	"testdata":     {},
	"node_modules": {},
}

// DiscoverModules walks root and returns every directory containing a
// go.mod file, in lexical order. Hidden directories (name starting with
// "."), vendor, testdata, and node_modules are skipped, and directory
// symlinks are not followed. Nested modules inside another module are
// returned as separate projects, since each has its own dependency graph.
func DiscoverModules(root string) ([]string, error) {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			_, skip := skipDirs[name]
			if path != root && (skip || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "go.mod" {
			dirs = append(dirs, filepath.Dir(path))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover modules under %s: %w", root, err)
	}
	return dirs, nil
}
