package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// capslockFixture is real `capslock -output json` output (v0.3.2) for a
// module whose main package calls http.Get and exec.Command, trimmed to
// the fields the parser reads plus the surrounding ones it must ignore.
const capslockFixture = `{
	"capabilityInfo": [
		{
			"packageName": "main",
			"capabilityName": "NETWORK",
			"capability": "CAPABILITY_NETWORK",
			"depPath": "example.com/capmod.main net/http.Get",
			"path": [
				{"name": "example.com/capmod.main", "package": "example.com/capmod"},
				{"name": "net/http.Get", "site": {"filename": "main.go", "line": "9"}, "package": "net/http"}
			],
			"packageDir": "example.com/capmod",
			"capabilityType": "CAPABILITY_TYPE_DIRECT"
		},
		{
			"packageName": "main",
			"capabilityName": "EXEC",
			"capability": "CAPABILITY_EXEC",
			"path": [
				{"name": "example.com/capmod.main", "package": "example.com/capmod"},
				{"name": "os/exec.Command", "package": "os/exec"}
			],
			"packageDir": "example.com/capmod",
			"capabilityType": "CAPABILITY_TYPE_DIRECT"
		},
		{
			"packageName": "main",
			"capability": "CAPABILITY_REFLECT",
			"path": [{"name": "example.com/capmod.main"}],
			"packageDir": "example.com/capmod"
		}
	],
	"packageInfo": [{"path": "example.com/capmod"}]
}`

// fakeCapslock puts an executable shell script named capslock on PATH that
// prints the given JSON, so Capslock() runs end to end without the real
// analyzer.
func fakeCapslock(t *testing.T, output string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary harness uses a shell script")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\ncat << 'JSONEOF'\n" + output + "\nJSONEOF\n"
	if err := os.WriteFile(filepath.Join(dir, "capslock"), []byte(script), 0o700); err != nil { // #nosec G306 -- the fake tool must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// capslockProject builds a project dir with a go.sum to fingerprint.
func capslockProject(t *testing.T, gosum string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/capmod\n\ngo 1.23\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(gosum), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeBaseline(t *testing.T, dir string, b capslockBaseline) {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, capslockBaselineName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestParseCapslockOutput(t *testing.T) {
	caps, err := parseCapslockOutput([]byte(capslockFixture))
	if err != nil {
		t.Fatal(err)
	}
	pkg := caps["example.com/capmod"]
	if pkg == nil {
		t.Fatalf("package missing: %v", caps)
	}
	if via := pkg["NETWORK"]; via != "net/http.Get" {
		t.Errorf("NETWORK via = %q, want net/http.Get", via)
	}
	if _, ok := pkg["EXEC"]; !ok {
		t.Error("EXEC capability missing")
	}
	if _, ok := pkg["REFLECT"]; !ok {
		t.Error("REFLECT capability missing")
	}
	if _, err := parseCapslockOutput([]byte("not json")); err == nil {
		t.Error("malformed output should error")
	}
}

func TestDiffCapabilities(t *testing.T) {
	old := map[string][]string{"example.com/capmod": {"FILES", "REFLECT"}}
	current := map[string]map[string]string{
		"example.com/capmod": {"FILES": "", "NETWORK": "net/http.Get", "UNANALYZED": ""},
		"example.com/newpkg": {"EXEC": "os/exec.Command"},
	}
	gains, lost := diffCapabilities(old, current)
	if len(gains) != 2 {
		t.Fatalf("gains = %+v, want NETWORK and EXEC (UNANALYZED ignored)", gains)
	}
	for _, g := range gains {
		if !highRiskCapabilities[g.capability] {
			t.Errorf("unexpected gain %+v", g)
		}
	}
	if lost != 1 { // REFLECT disappeared
		t.Errorf("lost = %d, want 1", lost)
	}
}

func TestDiffOrdersHighRiskFirst(t *testing.T) {
	old := map[string][]string{}
	current := map[string]map[string]string{
		"a.example/pkg": {"FILES": "", "NETWORK": ""},
	}
	gains, _ := diffCapabilities(old, current)
	if len(gains) != 2 || gains[0].capability != "NETWORK" {
		t.Errorf("high-risk gain should sort first: %+v", gains)
	}
}

func TestGainIssuesSeverity(t *testing.T) {
	issues := gainIssues([]capGain{
		{pkg: "p", capability: "NETWORK", via: "net/http.Get"},
		{pkg: "p", capability: "REFLECT"},
	})
	if !issues[0].Security {
		t.Error("gained NETWORK must be a security finding")
	}
	if issues[1].Security {
		t.Error("gained REFLECT must not be a security finding")
	}
	if !strings.Contains(issues[0].Detail, "gained NETWORK") || !strings.Contains(issues[0].Detail, "net/http.Get") {
		t.Errorf("detail = %q", issues[0].Detail)
	}
}

func TestCapslockFirstRunRecordsBaseline(t *testing.T) {
	fakeCapslock(t, capslockFixture)
	dir := capslockProject(t, "dep v1.0.0 h1:abc\n")

	issues, notes := Capslock(context.Background(), dir, false)
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "baseline recorded") {
		t.Fatalf("notes missing baseline-recorded: %v", notes)
	}
	var highRisk int
	for _, is := range issues {
		if is.Security {
			t.Errorf("first-run issue must not be Security: %+v", is)
		}
		if strings.Contains(is.Detail, "uses NETWORK") || strings.Contains(is.Detail, "uses EXEC") {
			highRisk++
		}
		if strings.Contains(is.Detail, "REFLECT") {
			t.Errorf("non-high-risk capability reported on first run: %+v", is)
		}
	}
	if highRisk != 2 {
		t.Errorf("want NETWORK and EXEC reported, got %+v", issues)
	}

	raw, err := os.ReadFile(filepath.Join(dir, capslockBaselineName))
	if err != nil {
		t.Fatalf("baseline not written: %v", err)
	}
	var b capslockBaseline
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	if b.Version != capslockBaselineVersion || b.GoSumSHA256 == "" || b.GOOS == "" {
		t.Errorf("baseline metadata incomplete: %+v", b)
	}
	caps := b.Capabilities["example.com/capmod"]
	if len(caps) != 3 {
		t.Errorf("baseline capabilities = %v", caps)
	}
}

func TestCapslockSkipsWhenGosumUnchanged(t *testing.T) {
	fakeCapslock(t, capslockFixture)
	dir := capslockProject(t, "dep v1.0.0 h1:abc\n")

	if _, notes := Capslock(context.Background(), dir, false); !strings.Contains(strings.Join(notes, "\n"), "baseline recorded") {
		t.Fatalf("first run should record: %v", notes)
	}
	issues, notes := Capslock(context.Background(), dir, false)
	if len(issues) != 0 {
		t.Errorf("second run should report nothing: %+v", issues)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "dependencies unchanged since baseline; skipped") {
		t.Errorf("missing skip note: %v", notes)
	}
}

func TestCapslockReportsGainedCapability(t *testing.T) {
	fakeCapslock(t, capslockFixture)
	dir := capslockProject(t, "dep v1.1.0 h1:new\n")
	writeBaseline(t, dir, capslockBaseline{
		Version:      capslockBaselineVersion,
		CreatedAt:    time.Now().UTC(),
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
		GoSumSHA256:  "stale-hash-so-capslock-runs",
		Capabilities: map[string][]string{"example.com/capmod": {"EXEC", "REFLECT"}},
	})

	issues, _ := Capslock(context.Background(), dir, false)
	var gained []Issue
	for _, is := range issues {
		if strings.Contains(is.Detail, "gained") {
			gained = append(gained, is)
		}
	}
	if len(gained) != 1 || !strings.Contains(gained[0].Detail, "gained NETWORK") {
		t.Fatalf("want exactly a gained-NETWORK finding, got %+v", issues)
	}
	if !gained[0].Security {
		t.Error("a gained high-risk capability must be a security finding")
	}

	// The baseline must NOT have been silently updated: the alert has to
	// repeat until the user accepts it.
	raw, _ := os.ReadFile(filepath.Join(dir, capslockBaselineName))
	if strings.Contains(string(raw), "NETWORK") {
		t.Error("baseline was updated after reporting a gain")
	}
}

func TestCapslockRefreshesBaselineWhenNoGains(t *testing.T) {
	fakeCapslock(t, capslockFixture)
	dir := capslockProject(t, "dep v1.1.0 h1:new\n")
	writeBaseline(t, dir, capslockBaseline{
		Version:      capslockBaselineVersion,
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
		GoSumSHA256:  "stale-hash-so-capslock-runs",
		Capabilities: map[string][]string{"example.com/capmod": {"EXEC", "NETWORK", "REFLECT"}},
	})

	issues, notes := Capslock(context.Background(), dir, false)
	if len(issues) != 0 {
		t.Errorf("no gains: nothing to report, got %+v", issues)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "baseline refreshed") {
		t.Errorf("missing refresh note: %v", notes)
	}
	var b capslockBaseline
	raw, _ := os.ReadFile(filepath.Join(dir, capslockBaselineName))
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	if b.GoSumSHA256 == "stale-hash-so-capslock-runs" {
		t.Error("baseline go.sum hash not refreshed")
	}
}

func TestCapslockUpdateBaselinesAcceptsGains(t *testing.T) {
	fakeCapslock(t, capslockFixture)
	dir := capslockProject(t, "dep v1.0.0 h1:abc\n")
	writeBaseline(t, dir, capslockBaseline{
		Version:      capslockBaselineVersion,
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
		GoSumSHA256:  "anything",
		Capabilities: map[string][]string{"example.com/capmod": {"EXEC"}},
	})

	issues, notes := Capslock(context.Background(), dir, true)
	for _, is := range issues {
		if strings.Contains(is.Detail, "gained") || is.Security {
			t.Errorf("update run must not report gains: %+v", is)
		}
	}
	if !strings.Contains(strings.Join(notes, "\n"), "baseline recorded") {
		t.Errorf("missing re-record note: %v", notes)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, capslockBaselineName))
	if !strings.Contains(string(raw), "NETWORK") {
		t.Error("updated baseline should include the current capabilities")
	}
}

func TestCapslockCorruptBaselineReRecords(t *testing.T) {
	fakeCapslock(t, capslockFixture)
	dir := capslockProject(t, "dep v1.0.0 h1:abc\n")
	if err := os.WriteFile(filepath.Join(dir, capslockBaselineName), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, notes := Capslock(context.Background(), dir, false)
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "baseline unusable") || !strings.Contains(joined, "baseline recorded") {
		t.Errorf("corrupt baseline should be reported and re-recorded: %v", notes)
	}
}

func TestCapslockNotInstalled(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, notes := Capslock(context.Background(), t.TempDir(), false)
	if len(notes) != 1 || !strings.Contains(notes[0], "capslock not installed; skipped") {
		t.Errorf("notes = %v", notes)
	}
}

func TestCapslockBrokenBinaryDegradesToNote(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary harness uses a shell script")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\necho 'boom: cannot load packages' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "capslock"), []byte(script), 0o700); err != nil { // #nosec G306 -- the fake tool must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	issues, notes := Capslock(context.Background(), capslockProject(t, ""), false)
	if len(issues) != 0 {
		t.Errorf("a failed run must not produce issues: %+v", issues)
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "boom") || !strings.Contains(joined, "skipped") {
		t.Errorf("failure should surface as a skip note: %v", notes)
	}
}
