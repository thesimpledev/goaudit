package modgraph

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestDiscoverModules(t *testing.T) {
	root := t.TempDir()
	write := func(rel string) {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("module x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a/go.mod")
	write("a/nested/go.mod")
	write("b/c/go.mod")
	write("vendor/x/go.mod")
	write(".hidden/y/go.mod")
	write("b/testdata/z/go.mod")
	write("b/node_modules/w/go.mod")

	dirs, err := DiscoverModules(root)
	if err != nil {
		t.Fatalf("DiscoverModules: %v", err)
	}
	want := []string{
		filepath.Join(root, "a"),
		filepath.Join(root, "a", "nested"),
		filepath.Join(root, "b", "c"),
	}
	if !slices.Equal(dirs, want) {
		t.Errorf("dirs = %v, want %v", dirs, want)
	}
}

func TestDiscoverModulesEmpty(t *testing.T) {
	dirs, err := DiscoverModules(t.TempDir())
	if err != nil {
		t.Fatalf("DiscoverModules: %v", err)
	}
	if len(dirs) != 0 {
		t.Errorf("dirs = %v, want none", dirs)
	}
}

func TestDiscoverModulesMissingRoot(t *testing.T) {
	if _, err := DiscoverModules(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected an error for a missing root")
	}
}
