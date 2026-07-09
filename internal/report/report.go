// Package report renders audit findings as human-readable text or JSON.
package report

import (
	"sort"

	"github.com/thesimpledev/goaudit/internal/checks"
	"github.com/thesimpledev/goaudit/internal/match"
)

// Report is the full outcome of one audit run: dependency findings from
// the IOC/typosquat scan plus issues from the external check suite.
type Report struct {
	Path     string
	IOCCount int
	Notes    []string
	Findings []match.Finding
	Issues   []checks.Issue
}

// New assembles a Report with findings sorted worst-first, then by module
// path, and check-suite issues sorted security-first.
func New(path string, iocCount int, notes []string, findings []match.Finding, issues []checks.Issue) *Report {
	sorted := make([]match.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Status != sorted[j].Status {
			return sorted[i].Status > sorted[j].Status
		}
		return sorted[i].Module < sorted[j].Module
	})
	sortedIssues := make([]checks.Issue, len(issues))
	copy(sortedIssues, issues)
	sort.SliceStable(sortedIssues, func(i, j int) bool {
		return sortedIssues[i].Security && !sortedIssues[j].Security
	})
	return &Report{Path: path, IOCCount: iocCount, Notes: notes, Findings: sorted, Issues: sortedIssues}
}

// IssueCounts splits the check-suite entries into security findings
// (gosec, govulncheck) and ordinary issues.
func (r *Report) IssueCounts() (security, issues int) {
	for _, is := range r.Issues {
		if is.Security {
			security++
		} else {
			issues++
		}
	}
	return security, issues
}

// Counts returns how many findings are flagged, warnings, and clean.
func (r *Report) Counts() (flagged, warnings, clean int) {
	for _, f := range r.Findings {
		switch f.Status {
		case match.Flagged:
			flagged++
		case match.Warning:
			warnings++
		default:
			clean++
		}
	}
	return flagged, warnings, clean
}
