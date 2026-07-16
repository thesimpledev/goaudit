package report

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/thesimpledev/goaudit/internal/checks"
)

// firstLine returns the first line of a possibly multi-line message and
// how many further lines were dropped.
func firstLine(s string) (string, int) {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[0], len(lines) - 1
}

// ProjectResult is one project's outcome within a multi-project audit.
// Err is set when the project could not be scanned; Report is set
// otherwise.
type ProjectResult struct {
	Name   string
	Dir    string
	Err    error
	Report *Report
}

// MultiReport groups the outcome of auditing every project found under a
// root directory.
type MultiReport struct {
	Root     string
	IOCCount int
	Notes    []string
	Projects []ProjectResult
}

// NewMulti assembles a MultiReport. iocCount is the size of the shared
// IOC set; per-project additions show up in each project's own notes.
func NewMulti(root string, iocCount int, notes []string, projects []ProjectResult) *MultiReport {
	return &MultiReport{Root: root, IOCCount: iocCount, Notes: notes, Projects: projects}
}

// TotalCounts aggregates results across every project in a multi-project
// audit.
type TotalCounts struct {
	Flagged  int
	Warnings int
	Security int
	Issues   int
	Clean    int
	Failed   int
}

// Totals sums finding and issue counts across all projects.
func (m *MultiReport) Totals() TotalCounts {
	var t TotalCounts
	for _, p := range m.Projects {
		if p.Err != nil {
			t.Failed++
			continue
		}
		flagged, warnings, clean := p.Report.Counts()
		security, issues := p.Report.IssueCounts()
		t.Flagged += flagged
		t.Warnings += warnings
		t.Security += security
		t.Issues += issues
		t.Clean += clean
	}
	return t
}

// WriteText renders the combined report for humans, one section per
// project. Clean modules are listed only when verbose is true; full
// lifts the per-tool cap on issue lines.
func (m *MultiReport) WriteText(w io.Writer, verbose, full bool) error {
	p := &printer{w: w}
	p.printf("goaudit multi-project audit: %s\n", m.Root)
	p.printf("projects found: %d | shared IOC entries: %d\n", len(m.Projects), m.IOCCount)
	for _, note := range m.Notes {
		p.printf("note: %s\n", note)
	}
	for _, pr := range m.Projects {
		writeProjectSection(p, pr, verbose, full)
	}
	t := m.Totals()
	p.printf("\noverall: %d projects, %d modules checked | %d flagged, %d warning(s), %d security finding(s), %d issue(s), %d failed\n",
		len(m.Projects), t.Flagged+t.Warnings+t.Clean, t.Flagged, t.Warnings, t.Security, t.Issues, t.Failed)
	return p.err
}

func writeProjectSection(p *printer, pr ProjectResult, verbose, full bool) {
	p.printf("\n── %s (%s)\n", pr.Name, pr.Dir)
	if pr.Err != nil {
		line, more := firstLine(pr.Err.Error())
		p.printf("   ERROR: %s\n", line)
		if more > 0 {
			p.printf("   (%d more lines; full error in the JSON report)\n", more)
		}
		return
	}
	for _, note := range pr.Report.Notes {
		p.printf("   note: %s\n", note)
	}
	writeFindings(p, pr.Report.Findings, verbose, "   ")
	writeIssues(p, pr.Report.Issues, "   ", full)
	flagged, warnings, clean := pr.Report.Counts()
	security, issues := pr.Report.IssueCounts()
	if flagged == 0 && warnings == 0 && security == 0 && issues == 0 {
		p.printf("   result: all %d modules clean, all checks passed\n", clean)
	} else {
		p.printf("   result: %d flagged, %d warning(s), %d security finding(s), %d issue(s), %d clean\n",
			flagged, warnings, security, issues, clean)
	}
}

type jsonProject struct {
	Name     string         `json:"name"`
	Dir      string         `json:"dir"`
	Error    string         `json:"error,omitempty"`
	Scanned  int            `json:"scanned"`
	Flagged  int            `json:"flagged"`
	Warnings int            `json:"warnings"`
	Security int            `json:"security"`
	Issues   int            `json:"issues"`
	Clean    int            `json:"clean"`
	Notes    []string       `json:"notes,omitempty"`
	Findings []jsonFinding  `json:"findings,omitempty"`
	Checks   []checks.Issue `json:"checks,omitempty"`
}

type jsonTotals struct {
	Projects int `json:"projects"`
	Flagged  int `json:"flagged"`
	Warnings int `json:"warnings"`
	Security int `json:"security"`
	Issues   int `json:"issues"`
	Clean    int `json:"clean"`
	Failed   int `json:"failed"`
}

type jsonMultiReport struct {
	Root     string        `json:"root"`
	IOCCount int           `json:"ioc_entries"`
	Notes    []string      `json:"notes,omitempty"`
	Projects []jsonProject `json:"projects"`
	Totals   jsonTotals    `json:"totals"`
}

// WriteJSON renders the combined report as indented JSON. Clean modules
// are included only when verbose is true.
func (m *MultiReport) WriteJSON(w io.Writer, verbose bool) error {
	out := jsonMultiReport{
		Root:     m.Root,
		IOCCount: m.IOCCount,
		Notes:    m.Notes,
		Projects: []jsonProject{},
	}
	for _, pr := range m.Projects {
		out.Projects = append(out.Projects, jsonProjectFrom(pr, verbose))
	}
	t := m.Totals()
	out.Totals = jsonTotals{
		Projects: len(m.Projects),
		Flagged:  t.Flagged,
		Warnings: t.Warnings,
		Security: t.Security,
		Issues:   t.Issues,
		Clean:    t.Clean,
		Failed:   t.Failed,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func jsonProjectFrom(pr ProjectResult, verbose bool) jsonProject {
	jp := jsonProject{Name: pr.Name, Dir: pr.Dir}
	if pr.Err != nil {
		jp.Error = pr.Err.Error()
		return jp
	}
	flagged, warnings, clean := pr.Report.Counts()
	security, issues := pr.Report.IssueCounts()
	jp.Scanned = flagged + warnings + clean
	jp.Flagged = flagged
	jp.Warnings = warnings
	jp.Security = security
	jp.Issues = issues
	jp.Clean = clean
	jp.Notes = pr.Report.Notes
	jp.Findings = jsonFindings(pr.Report.Findings, verbose)
	jp.Checks = pr.Report.Issues
	return jp
}
