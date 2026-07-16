package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/thesimpledev/goaudit/internal/checks"
	"github.com/thesimpledev/goaudit/internal/match"
)

func multiFixture() *MultiReport {
	flaggedRep := New("/root/evil-proj", 5, []string{"local note"}, []match.Finding{
		{Module: "github.com/evil/pkg", Version: "v1.2.3", Status: match.Flagged, Rule: "ioc", Detail: "exact match"},
		{Module: "github.com/ok/dep", Version: "v1.0.0", Status: match.Clean},
	}, []checks.Issue{{Tool: "errcheck", Detail: "main.go:5:2: unchecked error"}})
	cleanRep := New("/root/clean-proj", 5, nil, []match.Finding{
		{Module: "github.com/ok/dep", Version: "v1.0.0", Status: match.Clean},
	}, nil)
	return NewMulti("/root", 5, []string{"feed note"}, []ProjectResult{
		{Name: "owner/evil-proj", Dir: "/root/evil-proj", Report: flaggedRep},
		{Name: "clean-proj", Dir: "/root/clean-proj", Report: cleanRep},
		{Name: "broken", Dir: "/root/broken", Err: errors.New("go list failed")},
	})
}

func TestMultiTotals(t *testing.T) {
	got := multiFixture().Totals()
	want := TotalCounts{Flagged: 1, Warnings: 0, Security: 0, Issues: 1, Clean: 2, Failed: 1}
	if got != want {
		t.Fatalf("Totals = %+v, want %+v", got, want)
	}
}

func TestMultiWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := multiFixture().WriteText(&buf, false, false); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"goaudit multi-project audit: /root",
		"projects found: 3 | shared IOC entries: 5",
		"note: feed note",
		"── owner/evil-proj (/root/evil-proj)",
		"note: local note",
		"FLAGGED  github.com/evil/pkg@v1.2.3",
		"ISSUE    [errcheck] main.go:5:2: unchecked error",
		"result: 1 flagged, 0 warning(s), 0 security finding(s), 1 issue(s), 1 clean",
		"── clean-proj (/root/clean-proj)",
		"result: all 1 modules clean, all checks passed",
		"── broken (/root/broken)",
		"ERROR: go list failed",
		"overall: 3 projects, 3 modules checked | 1 flagged, 0 warning(s), 0 security finding(s), 1 issue(s), 1 failed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "github.com/ok/dep") {
		t.Error("clean module listed without verbose")
	}
}

func TestMultiWriteTextTruncatesLongErrors(t *testing.T) {
	long := errors.New("go list -m all failed: first line\nsecond line\nthird line")
	m := NewMulti("/root", 0, nil, []ProjectResult{
		{Name: "noisy", Dir: "/root/noisy", Err: long},
	})
	var buf bytes.Buffer
	if err := m.WriteText(&buf, false, false); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ERROR: go list -m all failed: first line") {
		t.Errorf("first line missing:\n%s", out)
	}
	if !strings.Contains(out, "(2 more lines; full error in the JSON report)") {
		t.Errorf("truncation notice missing:\n%s", out)
	}
	if strings.Contains(out, "second line") {
		t.Errorf("extra error lines should not appear in text output:\n%s", out)
	}
}

func TestMultiWriteTextVerbose(t *testing.T) {
	var buf bytes.Buffer
	if err := multiFixture().WriteText(&buf, true, false); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if !strings.Contains(buf.String(), "github.com/ok/dep") {
		t.Error("verbose output should list clean modules")
	}
}

func TestMultiWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := multiFixture().WriteJSON(&buf, false); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var got struct {
		Root     string `json:"root"`
		Projects []struct {
			Name    string `json:"name"`
			Dir     string `json:"dir"`
			Error   string `json:"error"`
			Flagged int    `json:"flagged"`
		} `json:"projects"`
		Totals struct {
			Projects int `json:"projects"`
			Flagged  int `json:"flagged"`
			Failed   int `json:"failed"`
		} `json:"totals"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if got.Root != "/root" || len(got.Projects) != 3 {
		t.Fatalf("unexpected report: %+v", got)
	}
	if got.Projects[0].Flagged != 1 || got.Projects[0].Name != "owner/evil-proj" {
		t.Errorf("first project wrong: %+v", got.Projects[0])
	}
	if got.Projects[2].Error != "go list failed" {
		t.Errorf("failed project missing error: %+v", got.Projects[2])
	}
	if got.Totals.Projects != 3 || got.Totals.Flagged != 1 || got.Totals.Failed != 1 {
		t.Errorf("totals wrong: %+v", got.Totals)
	}
}
