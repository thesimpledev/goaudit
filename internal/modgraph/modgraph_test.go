package modgraph

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	input := `{"Path":"example.com/main","Main":true}
{"Path":"github.com/foo/bar","Version":"v1.2.3","Indirect":true}
{"Path":"github.com/baz/qux","Version":"v0.1.0","Replace":{"Path":"github.com/fork/qux","Version":"v0.1.1"}}`
	mods, err := parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(mods) != 3 {
		t.Fatalf("len = %d, want 3", len(mods))
	}
	if !mods[0].Main {
		t.Error("first module should be Main")
	}
	if !mods[1].Indirect || mods[1].Version != "v1.2.3" {
		t.Errorf("second module parsed wrong: %+v", mods[1])
	}
	if mods[2].Replace == nil || mods[2].Replace.Path != "github.com/fork/qux" {
		t.Errorf("replace not parsed: %+v", mods[2])
	}
}

func TestParseBadJSON(t *testing.T) {
	if _, err := parse(strings.NewReader("not json")); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}

func TestVendored(t *testing.T) {
	dir := t.TempDir()
	if vendored(dir) {
		t.Error("bare dir should not look vendored")
	}
	if err := os.MkdirAll(filepath.Join(dir, "vendor"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vendor", "modules.txt"), []byte("# test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !vendored(dir) {
		t.Error("dir with vendor/modules.txt should look vendored")
	}
}

func TestIsTransient(t *testing.T) {
	transient := []string{
		`go list -m all failed: go: cloud.google.com/go@v0.112.2: Get "https://proxy.golang.org/...": dial tcp: lookup proxy.golang.org on 127.0.0.53:53: server misbehaving`,
		"read tcp 10.0.0.1:443: i/o timeout",
		"connection reset by peer",
		"net/http: TLS handshake timeout",
	}
	for _, msg := range transient {
		if !isTransient(msg) {
			t.Errorf("isTransient(%q) = false, want true", msg)
		}
	}
	permanent := []string{
		"go: errors parsing go.mod:\ngo.mod:1: unknown directive: this",
		"no go.mod in /tmp/x",
		"decode go list output: invalid character",
	}
	for _, msg := range permanent {
		if isTransient(msg) {
			t.Errorf("isTransient(%q) = true, want false", msg)
		}
	}
}

// TestPreserve proves the go.mod/go.sum snapshot survives the two ways
// `go list -mod=mod` can dirty a project: rewriting an existing file and
// creating one that was not there.
func TestPreserve(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	gosum := filepath.Join(dir, "go.sum")
	original := []byte("module example.test\n\ngo 1.23\n")
	if err := os.WriteFile(gomod, original, 0o600); err != nil {
		t.Fatal(err)
	}

	restore, err := preserve(gomod, gosum)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gomod, []byte("rewritten by the go tool\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gosum, []byte("example.com/dep v1.0.0/go.mod h1:xxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore()

	got, err := os.ReadFile(gomod)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Errorf("go.mod = %q, want original contents restored", got)
	}
	if _, err := os.Stat(gosum); !os.IsNotExist(err) {
		t.Errorf("go.sum should have been deleted again, stat err = %v", err)
	}
}

func TestListMissingGoMod(t *testing.T) {
	if _, err := List(context.Background(), t.TempDir()); err == nil {
		t.Fatal("expected an error for a directory without go.mod")
	}
}
