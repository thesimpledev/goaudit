package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeFeed points the run at a local feed server and an isolated data dir
// so tests never touch the real network or the user's feed data. The OSV
// feed is disabled; use fakeOSVFeed to serve one.
func fakeFeed(t *testing.T, body string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("GOAUDIT_FEED_URL", srv.URL)
	t.Setenv("GOAUDIT_OSV_FEED_URL", feedOff)
	t.Setenv("GOAUDIT_DATA_DIR", filepath.Join(t.TempDir(), "data"))
	// The external tool suite is exercised by the checks package tests;
	// running it here would make every end-to-end test minutes long.
	t.Setenv("GOAUDIT_SKIP_CHECKS", "1")
}

// makeOSVZip builds an OSV ecosystem export archive holding the given
// name→content members.
func makeOSVZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fakeOSVFeed serves an OSV export zip on a local server and points the OSV
// feed at it. Call after fakeFeed, which sets the isolated data dir.
func fakeOSVFeed(t *testing.T, files map[string]string) {
	t.Helper()
	body := makeOSVZip(t, files)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("GOAUDIT_OSV_FEED_URL", srv.URL)
}

const emptyFeed = `{"entries":[]}`

// setupVictimIn builds a throwaway project named name under root that
// requires requirePath, backed by a replace into the hidden .deps dir so
// `go list -m all` needs no network and discovery skips the fixture dep.
func setupVictimIn(t *testing.T, root, name, requirePath string) string {
	t.Helper()
	dep := filepath.Join(root, ".deps", name)
	writeFile(t, filepath.Join(dep, "go.mod"), "module "+requirePath+"\n\ngo 1.23\n")
	writeFile(t, filepath.Join(dep, "dep.go"), "// Package dep is a test fixture.\npackage dep\n")
	proj := filepath.Join(root, name)
	gomod := fmt.Sprintf("module github.com/testowner/%s\n\ngo 1.23\n\nrequire %s v1.0.0\n\nreplace %s => ../.deps/%s\n",
		name, requirePath, requirePath, name)
	writeFile(t, filepath.Join(proj, "go.mod"), gomod)
	return proj
}

// setupVictim builds a single throwaway project in its own temp dir.
func setupVictim(t *testing.T, requirePath string) string {
	t.Helper()
	return setupVictimIn(t, t.TempDir(), "proj", requirePath)
}

func TestRunFlagsExactIOC(t *testing.T) {
	fakeFeed(t, emptyFeed)
	proj := setupVictim(t, "github.com/evil/badpkg")
	writeFile(t, filepath.Join(proj, ".goaudit-ioc.json"),
		`{"entries":[{"module":"github.com/evil/badpkg","campaign":"PolinRider","reason":"test entry"}]}`)

	var out, errOut bytes.Buffer
	code := run([]string{"--path", proj}, &out, &errOut)
	if code != exitFlagged {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitFlagged, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "FLAGGED") || !strings.Contains(out.String(), "PolinRider") {
		t.Errorf("report missing expected content:\n%s", out.String())
	}
}

func TestRunCleanExitsZero(t *testing.T) {
	fakeFeed(t, emptyFeed)
	proj := setupVictim(t, "example.org/harmless/dep")
	var out, errOut bytes.Buffer
	code := run([]string{"--path", proj}, &out, &errOut)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitClean, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "all 1 modules clean") {
		t.Errorf("unexpected report:\n%s", out.String())
	}
}

func TestRunFailOnWarnTyposquat(t *testing.T) {
	fakeFeed(t, emptyFeed)
	proj := setupVictim(t, "github.com/strechr/testify")

	var out, errOut bytes.Buffer
	code := run([]string{"--path", proj}, &out, &errOut)
	if code != exitClean {
		t.Fatalf("without --fail-on-warn: exit = %d, want %d\nstderr: %s", code, exitClean, errOut.String())
	}
	if !strings.Contains(out.String(), "WARNING") {
		t.Errorf("typosquat warning missing:\n%s", out.String())
	}

	out.Reset()
	errOut.Reset()
	code = run([]string{"--path", proj, "--fail-on-warn"}, &out, &errOut)
	if code != exitWarnings {
		t.Fatalf("with --fail-on-warn: exit = %d, want %d", code, exitWarnings)
	}
}

func TestRunWritesJSONReport(t *testing.T) {
	fakeFeed(t, emptyFeed)
	proj := setupVictim(t, "github.com/evil/badpkg")
	writeFile(t, filepath.Join(proj, ".goaudit-ioc.json"),
		`{"entries":[{"module":"github.com/evil/badpkg"}]}`)

	var out, errOut bytes.Buffer
	code := run([]string{"--path", proj}, &out, &errOut)
	if code != exitFlagged {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitFlagged, errOut.String())
	}
	jsonPath := filepath.Join(proj, jsonReportName)
	if !strings.Contains(out.String(), jsonPath) {
		t.Errorf("text output does not mention the JSON report path:\n%s", out.String())
	}
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("JSON report not written: %v", err)
	}
	var rep struct {
		Flagged  int `json:"flagged"`
		Findings []struct {
			Module string `json:"module"`
			Status string `json:"status"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("JSON report is not valid JSON: %v\n%s", err, raw)
	}
	if rep.Flagged != 1 || len(rep.Findings) != 1 || rep.Findings[0].Module != "github.com/evil/badpkg" {
		t.Errorf("unexpected JSON report: %+v", rep)
	}
}

func TestFeedSocketCSVFlagsModule(t *testing.T) {
	fakeFeed(t, "Ecosystem,Namespace,Name,Version,Artifact,Published,Detected\n"+
		"npm,,evil-npm-pkg,1.0.0,,2025-01-01,2025-01-02\n"+
		"golang,github.com/evil,badpkg,v1.0.0,,2025-01-01,2025-01-02\n")
	proj := setupVictim(t, "github.com/evil/badpkg")

	var out, errOut bytes.Buffer
	code := run([]string{"--path", proj}, &out, &errOut)
	if code != exitFlagged {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitFlagged, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "Socket PolinRider feed refreshed: 1 Go entries") {
		t.Errorf("feed note missing:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "OSV malicious-package feed disabled") {
		t.Errorf("disabled OSV feed note missing:\n%s", out.String())
	}
}

func TestFeedCachedCopyUsedWhenFresh(t *testing.T) {
	fakeFeed(t, "Ecosystem,Namespace,Name,Version\ngolang,github.com/evil,badpkg,v1.0.0\n")
	proj := setupVictim(t, "github.com/evil/badpkg")

	var out, errOut bytes.Buffer
	if code := run([]string{"--path", proj}, &out, &errOut); code != exitFlagged {
		t.Fatalf("first run exit = %d\nstderr: %s", code, errOut.String())
	}

	// Second run must be served from the fresh cache, not the network.
	out.Reset()
	errOut.Reset()
	code := run([]string{"--path", proj}, &out, &errOut)
	if code != exitFlagged {
		t.Fatalf("second run exit = %d\nstderr: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "feed cache fresh") {
		t.Errorf("expected fresh-cache note:\n%s", out.String())
	}
}

func TestFeedDownWarnsAndContinues(t *testing.T) {
	t.Setenv("GOAUDIT_FEED_URL", "http://127.0.0.1:1/feed.csv")
	t.Setenv("GOAUDIT_OSV_FEED_URL", feedOff)
	t.Setenv("GOAUDIT_DATA_DIR", filepath.Join(t.TempDir(), "data"))
	t.Setenv("GOAUDIT_SKIP_CHECKS", "1")
	proj := setupVictim(t, "example.org/harmless/dep")

	var out, errOut bytes.Buffer
	code := run([]string{"--path", proj}, &out, &errOut)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d — a broken feed must not fail the scan\nstderr: %s", code, exitClean, errOut.String())
	}
	if !strings.Contains(out.String(), "WARNING: Socket PolinRider feed download failed") {
		t.Errorf("missing feed failure warning:\n%s", out.String())
	}
}

const testMALRecord = `{
  "id": "MAL-2026-3628",
  "summary": "Malicious code in github.com/evil/badpkg (Go)",
  "affected": [{
    "package": {"name": "github.com/evil/badpkg", "ecosystem": "Go"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
  }]
}`

func TestFeedOSVFlagsModule(t *testing.T) {
	fakeFeed(t, emptyFeed)
	fakeOSVFeed(t, map[string]string{
		"MAL-2026-3628.json": testMALRecord,
		"GO-2026-0001.json":  `{"id":"GO-2026-0001","summary":"a vulnerability, not malware"}`,
	})
	proj := setupVictim(t, "github.com/evil/badpkg")

	var out, errOut bytes.Buffer
	code := run([]string{"--path", proj}, &out, &errOut)
	if code != exitFlagged {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitFlagged, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "MAL-2026-3628") {
		t.Errorf("finding should cite the MAL record:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "OSV malicious-package feed refreshed: 1 Go entries") {
		t.Errorf("OSV feed note missing (the GO- record must not be counted):\n%s", out.String())
	}
}

func TestOneFeedDownOtherStillLoads(t *testing.T) {
	fakeFeed(t, emptyFeed)
	t.Setenv("GOAUDIT_FEED_URL", "http://127.0.0.1:1/feed.csv") // Socket unreachable
	fakeOSVFeed(t, map[string]string{"MAL-2026-3628.json": testMALRecord})
	proj := setupVictim(t, "github.com/evil/badpkg")

	var out, errOut bytes.Buffer
	code := run([]string{"--path", proj}, &out, &errOut)
	if code != exitFlagged {
		t.Fatalf("exit = %d, want %d — the OSV feed alone must still flag\nstdout: %s", code, exitFlagged, out.String())
	}
	if !strings.Contains(out.String(), "WARNING: Socket PolinRider feed download failed") {
		t.Errorf("missing Socket failure warning:\n%s", out.String())
	}
}

func TestOSVFeedDisabled(t *testing.T) {
	fakeFeed(t, emptyFeed) // sets GOAUDIT_OSV_FEED_URL=off
	proj := setupVictim(t, "example.org/harmless/dep")

	var out, errOut bytes.Buffer
	code := run([]string{"--path", proj}, &out, &errOut)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitClean, errOut.String())
	}
	if !strings.Contains(out.String(), "OSV malicious-package feed disabled") {
		t.Errorf("disabled note missing:\n%s", out.String())
	}
}

func TestReportWriteFailureWarnsNotFails(t *testing.T) {
	fakeFeed(t, emptyFeed)
	proj := setupVictim(t, "example.org/harmless/dep")
	if err := os.Chmod(proj, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(proj, 0o755) // let TempDir cleanup succeed
	})

	var out, errOut bytes.Buffer
	code := run([]string{"--path", proj}, &out, &errOut)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d — an unwritable report file must not fail the run\nstderr: %s", code, exitClean, errOut.String())
	}
	if !strings.Contains(errOut.String(), "WARNING: could not write") {
		t.Errorf("missing write-failure warning on stderr: %s", errOut.String())
	}
	if !strings.Contains(out.String(), "all 1 modules clean") {
		t.Errorf("text report should still have printed:\n%s", out.String())
	}
}

func TestExitFor(t *testing.T) {
	tests := []struct {
		name                    string
		flagged, security, soft int
		failOnWarn              bool
		want                    int
	}{
		{"clean", 0, 0, 0, false, exitClean},
		{"flagged dominates", 1, 5, 5, false, exitFlagged},
		{"security fails without fail-on-warn", 0, 1, 0, false, exitWarnings},
		{"soft passes by default", 0, 0, 7, false, exitClean},
		{"soft fails with fail-on-warn", 0, 0, 7, true, exitWarnings},
	}
	for _, tt := range tests {
		if got := exitFor(tt.flagged, tt.security, tt.soft, tt.failOnWarn); got != tt.want {
			t.Errorf("%s: exitFor = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestNameFromModule(t *testing.T) {
	tests := []struct{ module, dir, want string }{
		{"github.com/owner/repo", "/x/repo", "owner/repo"},
		{"golang.org/x/tools", "/x/tools", "x/tools"},
		{"gopkg.in/yaml.v3", "/x/yaml", "yaml.v3"},
		{"example.test/victim", "/x/v", "victim"},
		{"demo", "/x/folder", "folder"},
		{"", "/x/folder", "folder"},
	}
	for _, tt := range tests {
		if got := nameFromModule(tt.module, tt.dir); got != tt.want {
			t.Errorf("nameFromModule(%q, %q) = %q, want %q", tt.module, tt.dir, got, tt.want)
		}
	}
}

func TestRunMultiProject(t *testing.T) {
	fakeFeed(t, emptyFeed)
	root := t.TempDir()
	badproj := setupVictimIn(t, root, "badproj", "github.com/evil/badpkg")
	writeFile(t, filepath.Join(badproj, ".goaudit-ioc.json"),
		`{"entries":[{"module":"github.com/evil/badpkg","campaign":"PolinRider"}]}`)
	setupVictimIn(t, root, "cleanproj", "example.org/harmless/dep")
	writeFile(t, filepath.Join(root, "broken", "go.mod"), "this is not a valid go.mod\n")

	var out, errOut bytes.Buffer
	code := run([]string{"--path", root}, &out, &errOut)
	if code != exitFlagged {
		t.Fatalf("exit = %d, want %d — a flagged match dominates a failed project\nstdout: %s\nstderr: %s", code, exitFlagged, out.String(), errOut.String())
	}
	for _, want := range []string{
		"goaudit multi-project audit: " + root,
		"── testowner/badproj (",
		"FLAGGED  github.com/evil/badpkg@v1.0.0",
		"── testowner/cleanproj (",
		"── broken (",
		"ERROR:",
		"overall: 3 projects, 2 modules checked | 1 flagged",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
	if _, err := os.Stat(filepath.Join(root, jsonReportName)); err != nil {
		t.Errorf("JSON report not written at scan root: %v", err)
	}
}

func TestRunMultiOnlyBroken(t *testing.T) {
	fakeFeed(t, emptyFeed)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "broken", "go.mod"), "this is not a valid go.mod\n")

	var out, errOut bytes.Buffer
	code := run([]string{"--path", root}, &out, &errOut)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d — a failed project warns but must not fail the run\nstdout: %s", code, exitClean, out.String())
	}
	if !strings.Contains(out.String(), "ERROR:") {
		t.Errorf("output missing ERROR section:\n%s", out.String())
	}

	out.Reset()
	errOut.Reset()
	code = run([]string{"--path", root, "--fail-on-warn"}, &out, &errOut)
	if code != exitWarnings {
		t.Fatalf("with --fail-on-warn: exit = %d, want %d", code, exitWarnings)
	}
}

func TestRunMultiNoProjects(t *testing.T) {
	fakeFeed(t, emptyFeed)
	var out, errOut bytes.Buffer
	code := run([]string{"--path", t.TempDir()}, &out, &errOut)
	if code != exitError {
		t.Fatalf("exit = %d, want %d", code, exitError)
	}
	if !strings.Contains(errOut.String(), "no go.mod found under") {
		t.Errorf("stderr missing discovery error: %s", errOut.String())
	}
}

func TestRunRecursiveFlag(t *testing.T) {
	fakeFeed(t, emptyFeed)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module github.com/testowner/rootproj\n\ngo 1.23\n")
	setupVictimIn(t, root, "child", "example.org/some/dep")

	var out, errOut bytes.Buffer
	code := run([]string{"--path", root}, &out, &errOut)
	if code != exitClean {
		t.Fatalf("single mode: exit = %d\nstderr: %s", code, errOut.String())
	}
	if strings.Contains(out.String(), "multi-project") {
		t.Fatalf("dir with go.mod should scan single-project without --recursive:\n%s", out.String())
	}

	out.Reset()
	errOut.Reset()
	code = run([]string{"--path", root, "--recursive"}, &out, &errOut)
	if code != exitClean {
		t.Fatalf("recursive mode: exit = %d\nstderr: %s", code, errOut.String())
	}
	for _, want := range []string{"multi-project", "── testowner/rootproj (", "── testowner/child (", "2 projects"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("recursive output missing %q:\n%s", want, out.String())
		}
	}
}

func TestRunMultiRootAllowFile(t *testing.T) {
	fakeFeed(t, emptyFeed)
	root := t.TempDir()
	setupVictimIn(t, root, "warnproj", "github.com/strechr/testify")
	writeFile(t, filepath.Join(root, ".goaudit-ioc.json"),
		`{"allow":["github.com/strechr/testify"]}`)

	var out, errOut bytes.Buffer
	code := run([]string{"--path", root, "--fail-on-warn"}, &out, &errOut)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d — the root allow file should suppress the warning\nstdout: %s\nstderr: %s",
			code, exitClean, out.String(), errOut.String())
	}
	if strings.Contains(out.String(), "WARNING  github.com/strechr/testify") {
		t.Errorf("allowlisted module still warned:\n%s", out.String())
	}
}

func TestRunMultiJSONReport(t *testing.T) {
	fakeFeed(t, emptyFeed)
	root := t.TempDir()
	badproj := setupVictimIn(t, root, "badproj", "github.com/evil/badpkg")
	writeFile(t, filepath.Join(badproj, ".goaudit-ioc.json"),
		`{"entries":[{"module":"github.com/evil/badpkg"}]}`)

	var out, errOut bytes.Buffer
	code := run([]string{"--path", root}, &out, &errOut)
	if code != exitFlagged {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitFlagged, errOut.String())
	}
	raw, err := os.ReadFile(filepath.Join(root, jsonReportName))
	if err != nil {
		t.Fatalf("JSON report not written: %v", err)
	}
	var rep struct {
		Projects []struct {
			Name    string `json:"name"`
			Flagged int    `json:"flagged"`
		} `json:"projects"`
		Totals struct {
			Projects int `json:"projects"`
			Flagged  int `json:"flagged"`
		} `json:"totals"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("JSON report is not valid JSON: %v\n%s", err, raw)
	}
	if rep.Totals.Projects != 1 || rep.Totals.Flagged != 1 {
		t.Errorf("totals wrong: %+v", rep.Totals)
	}
	if rep.Projects[0].Name != "testowner/badproj" || rep.Projects[0].Flagged != 1 {
		t.Errorf("project wrong: %+v", rep.Projects[0])
	}
}

func TestParseSkipChecks(t *testing.T) {
	tests := []struct {
		value   string
		skipAll bool
		skip    []string
	}{
		{"", false, nil},
		{"1", true, nil},
		{"true", true, nil},
		{"yes", true, nil},
		{"capslock", false, []string{"capslock"}},
		{"test,capslock", false, []string{"test", "capslock"}},
		{"capslock,bogus", true, nil},
		{" Capslock ", false, []string{"capslock"}},
	}
	for _, tt := range tests {
		skipAll, skip := parseSkipChecks(tt.value)
		if skipAll != tt.skipAll {
			t.Errorf("parseSkipChecks(%q) skipAll = %v, want %v", tt.value, skipAll, tt.skipAll)
			continue
		}
		for _, name := range tt.skip {
			if !skip[name] {
				t.Errorf("parseSkipChecks(%q) should skip %q, got %v", tt.value, name, skip)
			}
		}
		if len(skip) != len(tt.skip) {
			t.Errorf("parseSkipChecks(%q) skip = %v, want %v", tt.value, skip, tt.skip)
		}
	}
}

func TestUpdateBaselinesFlag(t *testing.T) {
	var errOut bytes.Buffer
	opts, _, ok := parseFlags([]string{"--update-baselines", "--path", "x"}, &errOut)
	if !ok || !opts.updateBaselines {
		t.Errorf("flag not parsed: %+v (%s)", opts, errOut.String())
	}
	opts, _, ok = parseFlags([]string{"--path", "x"}, &errOut)
	if !ok || opts.updateBaselines {
		t.Errorf("flag should default to false: %+v", opts)
	}
}
