package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTidyFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestClassifyTidy(t *testing.T) {
	diff := "diff current/go.mod tidy/go.mod\n--- current/go.mod\n+++ tidy/go.mod\n@@ -3,5 +3,3 @@\n-require example.org/dep v1.0.0\n"
	issues, notes := classifyTidy([]byte(diff), nil)
	if len(issues) != 1 || len(notes) != 0 {
		t.Fatalf("drift: issues = %+v, notes = %v", issues, notes)
	}
	if issues[0].Tool != "tidy" || issues[0].Level != LevelWarning {
		t.Errorf("drift issue wrong: %+v", issues[0])
	}

	issues, notes = classifyTidy(nil, []byte("go: example.org/dep@v1.0.0: module lookup disabled by GOPROXY=off\n"))
	if len(issues) != 0 || len(notes) != 1 {
		t.Fatalf("failure: issues = %+v, notes = %v", issues, notes)
	}
	if !strings.Contains(notes[0], "tidy check skipped") || !strings.Contains(notes[0], "GOPROXY=off") {
		t.Errorf("failure note wrong: %q", notes[0])
	}
}

func TestTidyCleanModule(t *testing.T) {
	dir := t.TempDir()
	writeTidyFile(t, filepath.Join(dir, "go.mod"), "module example.test/tidyproj\n\ngo 1.23\n")
	writeTidyFile(t, filepath.Join(dir, "main.go"), "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"ok\") }\n")

	issues, notes := Tidy(context.Background(), dir)
	if len(issues) != 0 || len(notes) != 0 {
		t.Errorf("clean module: issues = %+v, notes = %v", issues, notes)
	}
}

// TestTidyDriftedModule uses an unused require backed by a filesystem
// replace, so the drift is detectable without any network access.
func TestTidyDriftedModule(t *testing.T) {
	dir := t.TempDir()
	writeTidyFile(t, filepath.Join(dir, "dep", "go.mod"), "module example.org/unused/dep\n\ngo 1.23\n")
	writeTidyFile(t, filepath.Join(dir, "dep", "dep.go"), "// Package dep is a test fixture.\npackage dep\n")
	writeTidyFile(t, filepath.Join(dir, "go.mod"),
		"module example.test/untidy\n\ngo 1.23\n\nrequire example.org/unused/dep v1.0.0\n\nreplace example.org/unused/dep => ./dep\n")
	writeTidyFile(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() {}\n")

	issues, notes := Tidy(context.Background(), dir)
	if len(notes) != 0 {
		t.Fatalf("drift check was skipped: %v", notes)
	}
	if len(issues) != 1 || issues[0].Tool != "tidy" || issues[0].Level != LevelWarning {
		t.Fatalf("issues = %+v, want one tidy warning", issues)
	}
}

func TestTidySkippedWhenGraphUnloadable(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOFLAGS", "")
	dir := t.TempDir()
	writeTidyFile(t, filepath.Join(dir, "go.mod"), "module example.test/offline\n\ngo 1.23\n")
	writeTidyFile(t, filepath.Join(dir, "main.go"),
		"package main\n\nimport _ \"example.invalid/never/fetched\"\n\nfunc main() {}\n")

	issues, notes := Tidy(context.Background(), dir)
	if len(issues) != 0 {
		t.Fatalf("an unloadable graph must not produce findings: %+v", issues)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "tidy check skipped") {
		t.Fatalf("notes = %v, want one skip note", notes)
	}
}
