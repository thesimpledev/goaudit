package report

import (
	"encoding/json"
	"io"

	"github.com/thesimpledev/goaudit/internal/checks"
	"github.com/thesimpledev/goaudit/internal/match"
)

type jsonFinding struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Status  string `json:"status"`
	Rule    string `json:"rule,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type jsonReport struct {
	Path     string         `json:"path"`
	Scanned  int            `json:"scanned"`
	Flagged  int            `json:"flagged"`
	Warnings int            `json:"warnings"`
	Security int            `json:"security"`
	Issues   int            `json:"issues"`
	Clean    int            `json:"clean"`
	IOCCount int            `json:"ioc_entries"`
	Notes    []string       `json:"notes,omitempty"`
	Findings []jsonFinding  `json:"findings"`
	Checks   []checks.Issue `json:"checks,omitempty"`
}

// WriteJSON renders the report as indented JSON. Clean modules are
// included only when verbose is true.
func (r *Report) WriteJSON(w io.Writer, verbose bool) error {
	flagged, warnings, clean := r.Counts()
	security, issues := r.IssueCounts()
	out := jsonReport{
		Path:     r.Path,
		Scanned:  flagged + warnings + clean,
		Flagged:  flagged,
		Warnings: warnings,
		Security: security,
		Issues:   issues,
		Clean:    clean,
		IOCCount: r.IOCCount,
		Notes:    r.Notes,
		Findings: jsonFindings(r.Findings, verbose),
		Checks:   r.Issues,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// jsonFindings converts findings for JSON output. Clean modules are
// included only when verbose is true.
func jsonFindings(findings []match.Finding, verbose bool) []jsonFinding {
	out := []jsonFinding{}
	for _, f := range findings {
		if f.Status == match.Clean && !verbose {
			continue
		}
		out = append(out, jsonFinding{
			Module:  f.Module,
			Version: f.Version,
			Status:  f.Status.String(),
			Rule:    f.Rule,
			Detail:  f.Detail,
		})
	}
	return out
}
