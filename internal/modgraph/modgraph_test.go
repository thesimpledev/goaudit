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

func TestListMissingGoMod(t *testing.T) {
	if _, err := List(context.Background(), t.TempDir()); err == nil {
		t.Fatal("expected an error for a directory without go.mod")
	}
}
