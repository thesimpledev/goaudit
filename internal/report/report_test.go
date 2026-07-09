package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/thesimpledev/goaudit/internal/checks"
	"github.com/thesimpledev/goaudit/internal/match"
)

func testFindings() []match.Finding {
	return []match.Finding{
		{Module: "github.com/ok/dep", Version: "v1.0.0", Status: match.Clean},
		{Module: "github.com/evil/pkg", Version: "v1.2.3", Status: match.Flagged, Rule: "ioc", Detail: "exact match"},
		{Module: "github.com/odd/dep", Version: "v0.1.0", Status: match.Warning, Rule: "typosquat", Detail: "near miss"},
	}
}

func TestNewSortsWorstFirst(t *testing.T) {
	r := New("/proj", 10, nil, testFindings(), nil)
	if r.Findings[0].Status != match.Flagged || r.Findings[2].Status != match.Clean {
		t.Fatalf("findings not sorted worst-first: %+v", r.Findings)
	}
}

func TestCounts(t *testing.T) {
	r := New("/proj", 10, nil, testFindings(), nil)
	flagged, warnings, clean := r.Counts()
	if flagged != 1 || warnings != 1 || clean != 1 {
		t.Fatalf("Counts = %d/%d/%d, want 1/1/1", flagged, warnings, clean)
	}
}

func TestWriteText(t *testing.T) {
	r := New("/proj", 10, []string{"a note"}, testFindings(), nil)
	var buf bytes.Buffer
	if err := r.WriteText(&buf, false); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"FLAGGED", "WARNING", "a note", "1 flagged, 1 warning(s), 0 security finding(s), 0 issue(s), 1 clean"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "github.com/ok/dep") {
		t.Error("clean module listed without verbose")
	}

	buf.Reset()
	if err := r.WriteText(&buf, true); err != nil {
		t.Fatalf("WriteText verbose: %v", err)
	}
	if !strings.Contains(buf.String(), "github.com/ok/dep") {
		t.Error("verbose output should list clean modules")
	}
}

func TestWriteTextAllClean(t *testing.T) {
	r := New("/proj", 0, nil, []match.Finding{{Module: "github.com/ok/dep", Status: match.Clean}}, nil)
	var buf bytes.Buffer
	if err := r.WriteText(&buf, false); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if !strings.Contains(buf.String(), "all 1 modules clean") {
		t.Errorf("unexpected clean summary:\n%s", buf.String())
	}
}

func TestWriteTextIssues(t *testing.T) {
	issues := []checks.Issue{
		{Tool: "staticcheck", Detail: "main.go:10:2: unused variable x (U1000)"},
		{Tool: "govulncheck", Detail: "GO-2026-5856: crypto/tls leak (stdlib@go1.26.4, fixed in go1.26.5)", Security: true},
	}
	r := New("/proj", 0, nil, []match.Finding{{Module: "github.com/ok/dep", Status: match.Clean}}, issues)
	var buf bytes.Buffer
	if err := r.WriteText(&buf, false); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"SECURITY [govulncheck] GO-2026-5856",
		"ISSUE    [staticcheck] main.go:10:2",
		"result: 0 flagged, 0 warning(s), 1 security finding(s), 1 issue(s), 1 clean",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "SECURITY") > strings.Index(out, "ISSUE") {
		t.Errorf("security findings should render before ordinary issues:\n%s", out)
	}
}

func TestWriteJSON(t *testing.T) {
	r := New("/proj", 10, []string{"a note"}, testFindings(), nil)
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf, false); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var got struct {
		Scanned  int `json:"scanned"`
		Flagged  int `json:"flagged"`
		Warnings int `json:"warnings"`
		Findings []struct {
			Module string `json:"module"`
			Status string `json:"status"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if got.Scanned != 3 || got.Flagged != 1 || got.Warnings != 1 {
		t.Errorf("summary = %+v", got)
	}
	if len(got.Findings) != 2 {
		t.Errorf("findings = %d, want 2 (clean excluded)", len(got.Findings))
	}
	if got.Findings[0].Status != "flagged" {
		t.Errorf("first finding status = %q, want flagged", got.Findings[0].Status)
	}
}
