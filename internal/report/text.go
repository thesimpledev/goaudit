package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/thesimpledev/goaudit/internal/checks"
	"github.com/thesimpledev/goaudit/internal/match"
)

// printer wraps a writer so formatting calls need only one error check at
// the end.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format, args...)
}

// WriteText renders the report for humans. Clean modules are listed only
// when verbose is true.
func (r *Report) WriteText(w io.Writer, verbose bool) error {
	p := &printer{w: w}
	flagged, warnings, clean := r.Counts()
	total := flagged + warnings + clean

	p.printf("goaudit audit: %s\n", r.Path)
	p.printf("modules scanned: %d | IOC entries: %d\n", total, r.IOCCount)
	for _, note := range r.Notes {
		p.printf("note: %s\n", note)
	}
	p.printf("\n")

	shown := writeFindings(p, r.Findings, verbose, "")
	shown += writeIssues(p, r.Issues, "")
	if shown > 0 {
		p.printf("\n")
	}

	security, issues := r.IssueCounts()
	if flagged == 0 && warnings == 0 && security == 0 && issues == 0 {
		p.printf("result: all %d modules clean, all checks passed\n", total)
	} else {
		p.printf("result: %d flagged, %d warning(s), %d security finding(s), %d issue(s), %d clean\n",
			flagged, warnings, security, issues, clean)
	}
	return p.err
}

// writeIssues prints one line per check-suite entry with the given
// indent — security findings labeled SECURITY, the rest ISSUE — and
// returns how many were shown.
func writeIssues(p *printer, issues []checks.Issue, indent string) int {
	for _, is := range issues {
		label := "ISSUE"
		if is.Security {
			label = "SECURITY"
		}
		p.printf("%s%-8s [%s] %s\n", indent, label, is.Tool, is.Detail)
	}
	return len(issues)
}

// writeFindings prints one line per finding with the given indent,
// returning how many findings were shown. Clean modules are included only
// when verbose is true.
func writeFindings(p *printer, findings []match.Finding, verbose bool, indent string) int {
	shown := 0
	for _, f := range findings {
		if f.Status == match.Clean && !verbose {
			continue
		}
		shown++
		p.printf("%s%-8s %s@%s\n", indent, strings.ToUpper(f.Status.String()), f.Module, f.Version)
		if f.Detail != "" {
			p.printf("%s         %s\n", indent, f.Detail)
		}
	}
	return shown
}
