package checks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseGofmt(t *testing.T) {
	out := []byte("main.go\ncmd/tool/util.go\nvendor/dep/x.go\n.hidden/y.go\ntestdata/z.go\n")
	issues := parseGofmt("/proj", out, nil, 0)
	if len(issues) != 2 {
		t.Fatalf("issues = %+v, want 2 (vendor/hidden/testdata skipped)", issues)
	}
	if !strings.Contains(issues[0].Detail, "main.go") {
		t.Errorf("first issue = %+v", issues[0])
	}
}

func TestParseGofix(t *testing.T) {
	diff := []byte(`--- /proj/main.go (old)
+++ /proj/main.go (new)
@@ -2,3 +2,3 @@
-func echo(v interface{}) interface{} { return v }
+func echo(v any) any { return v }
--- /proj/main.go (old)
+++ /proj/main.go (new)
@@ -8,3 +8,3 @@
-	var x interface{} = 1
+	var x any = 1
--- /proj/sub/util.go (old)
+++ /proj/sub/util.go (new)
@@ -1,1 +1,1 @@
-old
+new
--- /proj/vendor/dep/x.go (old)
+++ /proj/vendor/dep/x.go (new)
@@ -1,1 +1,1 @@
-old
+new
`)
	issues := parseGofix("/proj", diff, nil, 1)
	if len(issues) != 1 {
		t.Fatalf("issues = %+v, want one summary line", issues)
	}
	if !strings.Contains(issues[0].Detail, "2 file(s)") {
		t.Errorf("detail = %q, want a 2-file summary (main.go deduped, vendor skipped)", issues[0].Detail)
	}
	if strings.Contains(issues[0].Detail, "interface{}") {
		t.Errorf("detail = %q, diff hunks must not leak into the report", issues[0].Detail)
	}

	if issues := parseGofix("/proj", nil, nil, 0); issues != nil {
		t.Errorf("exit 0 should mean no issues, got %+v", issues)
	}
	vendorOnly := []byte("--- /proj/vendor/dep/x.go (old)\n+++ /proj/vendor/dep/x.go (new)\n@@ -1,1 +1,1 @@\n-old\n+new\n")
	if issues := parseGofix("/proj", vendorOnly, nil, 1); issues != nil {
		t.Errorf("vendor-only diff should be silent, got %+v", issues)
	}
	broken := parseGofix("/proj", nil, []byte("go: cannot find module\n"), 1)
	if len(broken) != 1 || broken[0].Detail != "go: cannot find module" {
		t.Errorf("failure without a diff should surface the error, got %+v", broken)
	}
}

// TestRunGofix exercises the real `go fix -diff` path against a fixture
// with a known modernization (interface{} -> any) and proves the audit
// only reports — the source file must be byte-identical afterwards.
func TestRunGofix(t *testing.T) {
	if !gofixSupportsDiff() {
		t.Skip("installed go toolchain has no `go fix -diff` (needs Go 1.26+)")
	}
	dir := t.TempDir()
	src := "package fixture\n\nfunc Echo(v interface{}) interface{} { return v }\n"
	for name, content := range map[string]string{
		"go.mod":  "module example.test/fixture\n\ngo 1.26\n",
		"main.go": src,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tools := []Tool{{Name: "gofix", Resolve: gofixArgs, Parse: parseGofix}}
	issues, notes := Run(context.Background(), dir, tools)
	if len(notes) != 0 {
		t.Errorf("unexpected notes: %v", notes)
	}
	if len(issues) != 1 || issues[0].Tool != "gofix" || !strings.Contains(issues[0].Detail, "1 file(s)") {
		t.Fatalf("issues = %+v, want one gofix summary naming 1 file", issues)
	}
	after, err := os.ReadFile(filepath.Join(dir, "main.go")) // #nosec G304 -- test-owned temp dir
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != src {
		t.Fatal("go fix modified the source file; the audit must never rewrite code")
	}
}

func TestLineParserGatesOnExitCode(t *testing.T) {
	parse := lineParser("staticcheck", false)
	if issues := parse("/proj", []byte("noise on success\n"), nil, 0); issues != nil {
		t.Errorf("exit 0 should mean no issues, got %+v", issues)
	}
	issues := parse("/proj", []byte("main.go:10:2: unused variable (U1000)\n# github.com/x/y\n"), nil, 1)
	if len(issues) != 1 || issues[0].Detail != "main.go:10:2: unused variable (U1000)" {
		t.Errorf("issues = %+v", issues)
	}
}

func TestLineParserEvenOnSuccess(t *testing.T) {
	parse := lineParser("revive", true)
	issues := parse("/proj", []byte("main.go:5:1: exported function X should have comment\n"), nil, 0)
	if len(issues) != 1 {
		t.Fatalf("revive warnings print with exit 0 and must still be reported: %+v", issues)
	}
}

func TestParseGosec(t *testing.T) {
	out := []byte(`{"Issues":[{"severity":"MEDIUM","rule_id":"G304","details":"Potential file inclusion via variable","file":"/proj/cmd/main.go","line":"42"}]}`)
	issues := parseGosec("/proj", out, nil, 1)
	if len(issues) != 1 {
		t.Fatalf("issues = %+v", issues)
	}
	want := "G304 (MEDIUM): Potential file inclusion via variable [cmd/main.go:42]"
	if issues[0].Detail != want {
		t.Errorf("detail = %q, want %q", issues[0].Detail, want)
	}
	if !issues[0].Security {
		t.Error("gosec findings must be marked as security findings")
	}
	if issues := parseGosec("/proj", []byte(`{"Issues":[]}`), nil, 0); len(issues) != 0 {
		t.Errorf("clean gosec run produced issues: %+v", issues)
	}
}

func TestParseGovulncheck(t *testing.T) {
	stream := `{"config":{"protocol_version":"v1.0.0"}}
{"progress":{"message":"Scanning..."}}
{"osv":{"id":"GO-2026-5856","summary":"Encrypted Client Hello privacy leak in crypto/tls"}}
{"osv":{"id":"GO-2024-9999","summary":"Unreached vulnerability"}}
{"finding":{"osv":"GO-2026-5856","fixed_version":"go1.26.5","trace":[{"module":"stdlib","version":"go1.26.4"}]}}
{"finding":{"osv":"GO-2026-5856","fixed_version":"go1.26.5","trace":[{"module":"stdlib","version":"go1.26.4","function":"Conn.Read"}]}}
{"finding":{"osv":"GO-2024-9999","trace":[{"module":"github.com/dep/x","version":"v1.0.0"}]}}
`
	issues := parseGovulncheck("/proj", []byte(stream), nil, 3)
	if len(issues) != 1 {
		t.Fatalf("issues = %+v, want only the called vulnerability", issues)
	}
	for _, want := range []string{"GO-2026-5856", "crypto/tls", "stdlib@go1.26.4", "fixed in go1.26.5"} {
		if !strings.Contains(issues[0].Detail, want) {
			t.Errorf("detail missing %q: %s", want, issues[0].Detail)
		}
	}
	if !issues[0].Security {
		t.Error("govulncheck findings must be marked as security findings")
	}
}

func TestParseGoTest(t *testing.T) {
	out := []byte(`=== RUN   TestFoo
--- FAIL: TestFoo (0.01s)
    foo_test.go:12: got 1, want 2
FAIL
FAIL	github.com/x/y/pkg	0.123s
ok  	github.com/x/y/other	0.045s
`)
	issues := parseGoTest("/proj", out, nil, 1)
	if len(issues) != 2 {
		t.Fatalf("issues = %+v, want --- FAIL line and FAIL pkg line", issues)
	}
	if issues := parseGoTest("/proj", []byte("ok  \tgithub.com/x/y\t0.1s\n"), nil, 0); len(issues) != 0 {
		t.Errorf("passing tests produced issues: %+v", issues)
	}
}

func TestCapIssues(t *testing.T) {
	var many []Issue
	for range 25 {
		many = append(many, Issue{Tool: "gosec", Detail: "x", Security: true})
	}
	capped := capIssues(many, "gosec")
	if len(capped) != maxIssuesPerTool+1 {
		t.Fatalf("len = %d, want %d", len(capped), maxIssuesPerTool+1)
	}
	marker := capped[maxIssuesPerTool]
	if !strings.Contains(marker.Detail, "+15 more gosec") {
		t.Errorf("truncation notice = %+v", marker)
	}
	if !marker.Security {
		t.Error("truncation marker should keep the tool's security level")
	}
}

// TestRunGofmtAndVet exercises the real execution path with the two tools
// that ship with Go itself, against a fixture with a known formatting
// problem.
func TestRunGofmtAndVet(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.test/fixture\n\ngo 1.23\n")
	write("main.go", "package main\n\nfunc main()    {\n}\n") // misformatted on purpose

	tools := []Tool{
		{Name: "gofmt", Args: []string{"gofmt", "-l", "."}, Parse: parseGofmt},
		{Name: "vet", Args: []string{"go", "vet", "./..."}, Parse: lineParser("vet", false)},
	}
	issues, notes := Run(context.Background(), dir, tools)
	if len(notes) != 0 {
		t.Errorf("unexpected notes: %v", notes)
	}
	if len(issues) != 1 || issues[0].Tool != "gofmt" {
		t.Fatalf("issues = %+v, want exactly the gofmt finding", issues)
	}
}

// TestRunChecksBuildablePackagesOnly proves a package that cannot build
// on this platform is skipped with a note while the rest of the module is
// still checked: the buildable package carries a real vet error that must
// surface even though ./... as a whole cannot compile.
func TestRunChecksBuildablePackagesOnly(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	foreign := "windows"
	if runtime.GOOS == "windows" {
		foreign = "linux"
	}
	write("go.mod", "module example.test/fixture\n\ngo 1.23\n")
	write("lib.go", "package fixture\n\nimport \"fmt\"\n\nfunc bad() string { return fmt.Sprintf(\"%d\", \"not a number\") }\n")
	// foreign fails at import loading: its sole import has no files on
	// this platform, the same shape as importing golang.org/x/sys/windows
	// when audited on Linux.
	write("platform/impl.go", "//go:build "+foreign+"\n\npackage platform\n")
	write("foreign/foreign.go", "package foreign\n\nimport _ \"example.test/fixture/platform\"\n")
	// stub loads cleanly but fails to compile: the symbol it uses exists
	// only behind the other platform's build tag, the same shape as
	// Windows-only syscall.SysProcAttr fields.
	write("stub/stub.go", "package stub\n\nfunc Name() string { return platformName }\n")
	write("stub/impl.go", "//go:build "+foreign+"\n\npackage stub\n\nconst platformName = \""+foreign+"\"\n")

	tools := []Tool{{Name: "vet", Args: []string{"go", "vet", "./..."}, Parse: lineParser("vet", false)}}
	issues, notes := Run(context.Background(), dir, tools)
	if len(notes) != 1 || !strings.Contains(notes[0], "2 of 3") ||
		!strings.Contains(notes[0], "foreign") || !strings.Contains(notes[0], "stub") {
		t.Errorf("notes = %v, want one note naming both skipped packages", notes)
	}
	if len(issues) == 0 || issues[0].Tool != "vet" {
		t.Fatalf("issues = %+v, want the vet finding from the buildable package", issues)
	}
}

func TestRunSkipsPackagelessModule(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test/empty\n\ngo 1.23\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	issues, notes := Run(context.Background(), dir, []Tool{{Name: "vet", Args: []string{"go", "vet", "./..."}, Parse: lineParser("vet", false)}})
	if len(issues) != 0 {
		t.Errorf("issues = %+v, want none", issues)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "no Go packages") {
		t.Errorf("notes = %v, want the no-packages note", notes)
	}
}
