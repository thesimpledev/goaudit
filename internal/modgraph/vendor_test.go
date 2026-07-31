package modgraph

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestParseModulesTxt(t *testing.T) {
	input := `## workspace
# github.com/direct/dep v1.2.3
## explicit; go1.23
github.com/direct/dep
github.com/direct/dep/sub
# example.org/indirect/dep v0.4.0
example.org/indirect/dep
# example.org/replaced/dep v1.0.0 => example.org/fork/dep v1.0.1
## explicit; go1.23
example.org/replaced/dep
# example.org/local/dep v0.0.0 => ./local
example.org/local/dep
`
	mods := parseModulesTxt([]byte(input))
	if len(mods) != 4 {
		t.Fatalf("len = %d, want 4: %+v", len(mods), mods)
	}
	if mods[0].Path != "github.com/direct/dep" || mods[0].Version != "v1.2.3" || mods[0].Indirect {
		t.Errorf("explicit module parsed wrong: %+v", mods[0])
	}
	if mods[1].Path != "example.org/indirect/dep" || !mods[1].Indirect {
		t.Errorf("indirect module parsed wrong: %+v", mods[1])
	}
	if mods[2].Replace == nil || mods[2].Replace.Path != "example.org/fork/dep" || mods[2].Replace.Version != "v1.0.1" {
		t.Errorf("module replace parsed wrong: %+v", mods[2])
	}
	if mods[3].Replace == nil || mods[3].Replace.Path != "./local" || mods[3].Replace.Version != "" {
		t.Errorf("filesystem replace parsed wrong: %+v", mods[3])
	}
	for _, m := range mods {
		if m.Main {
			t.Errorf("no vendored module may be Main: %+v", m)
		}
	}
}

func TestModulePath(t *testing.T) {
	tests := []struct{ name, gomod, want string }{
		{"plain", "module example.com/proj\n\ngo 1.23\n", "example.com/proj"},
		{"comment", "// header\nmodule example.com/proj // trailing\n", "example.com/proj"},
		{"quoted", `module "example.com/proj"` + "\n", "example.com/proj"},
		{"prefix word", "modules example.com/no\nmodule example.com/yes\n", "example.com/yes"},
		{"missing", "go 1.23\n", ""},
	}
	for _, tt := range tests {
		if got := modulePath([]byte(tt.gomod)); got != tt.want {
			t.Errorf("%s: modulePath = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// TestListVendoredProject proves a vendored single-module project is
// listed from vendor/modules.txt alone: the fake dependency paths would
// fail any network lookup.
func TestListVendoredProject(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module example.test/proj\n\ngo 1.23\n\nrequire example.org/some/dep v1.0.0\n")
	write(t, filepath.Join(dir, "vendor", "modules.txt"),
		"# example.org/some/dep v1.0.0\n## explicit; go1.23\nexample.org/some/dep\n")

	mods, err := List(context.Background(), dir)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(mods) != 2 {
		t.Fatalf("len = %d, want 2: %+v", len(mods), mods)
	}
	if !mods[0].Main || mods[0].Path != "example.test/proj" {
		t.Errorf("main module wrong: %+v", mods[0])
	}
	if mods[1].Path != "example.org/some/dep" || mods[1].Version != "v1.0.0" {
		t.Errorf("dependency wrong: %+v", mods[1])
	}
}

// TestListWorkspaceVendored proves a member of a workspace-vendored
// monorepo is listed from the workspace's vendor/modules.txt, the one
// configuration where `go list -m all` cannot run at all.
func TestListWorkspaceVendored(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "go.work"), "go 1.23\n\nuse (\n\t./member\n\t./other\n)\n")
	write(t, filepath.Join(root, "vendor", "modules.txt"),
		"## workspace\n# example.org/shared/dep v2.1.0\n## explicit; go1.23\nexample.org/shared/dep\n")
	write(t, filepath.Join(root, "member", "go.mod"), "module example.test/member\n\ngo 1.23\n")
	write(t, filepath.Join(root, "other", "go.mod"), "module example.test/other\n\ngo 1.23\n")

	mods, err := List(context.Background(), filepath.Join(root, "member"))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(mods) != 2 {
		t.Fatalf("len = %d, want 2: %+v", len(mods), mods)
	}
	if !mods[0].Main || mods[0].Path != "example.test/member" {
		t.Errorf("main module wrong: %+v", mods[0])
	}
	if mods[1].Path != "example.org/shared/dep" || mods[1].Version != "v2.1.0" || mods[1].Indirect {
		t.Errorf("workspace dependency wrong: %+v", mods[1])
	}
}
