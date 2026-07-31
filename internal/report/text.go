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

// maxIssuesPerTool caps how many lines one tool may print in the text
// report so a messy repo cannot drown it. Suppressed lines are summed
// into one "+N more" line per tool; the counts in the result line and
// the JSON report always cover everything. --cli lifts the cap.
const maxIssuesPerTool = 10

// WriteText renders the report for humans. Clean modules are listed only
// when verbose is true; full lifts the per-tool cap on issue lines.
func (r *Report) WriteText(w io.Writer, verbose, full bool) error {
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
	shown += writeIssues(p, r.Issues, "", full)
	if shown > 0 {
		p.printf("\n")
	}

	security, checkWarnings, issues := r.IssueCounts()
	if flagged == 0 && warnings == 0 && security == 0 && checkWarnings == 0 && issues == 0 {
		p.printf("result: all %d modules clean, all checks passed\n", total)
	} else {
		p.printf("result: %d flagged, %d warning(s), %d security finding(s), %d issue(s), %d clean\n",
			flagged, warnings+checkWarnings, security, issues, clean)
	}
	return p.err
}

// writeIssues prints one line per check-suite entry with the given
// indent, labeled by level, and returns how many lines were printed.
// Unless full is set, each tool prints at most maxIssuesPerTool lines;
// the rest collapse into one "+N more" line per tool after the list,
// carrying the worst level among the lines it stands for.
func writeIssues(p *printer, issues []checks.Issue, indent string, full bool) int {
	shown := 0
	printed := map[string]int{}
	hidden := map[string]int{}
	hiddenLevel := map[string]checks.Level{}
	var hiddenOrder []string
	for _, is := range issues {
		if !full && printed[is.Tool] >= maxIssuesPerTool {
			if hidden[is.Tool] == 0 {
				hiddenOrder = append(hiddenOrder, is.Tool)
				hiddenLevel[is.Tool] = is.Level
			}
			hidden[is.Tool]++
			if levelRank(is.Level) > levelRank(hiddenLevel[is.Tool]) {
				hiddenLevel[is.Tool] = is.Level
			}
			continue
		}
		printed[is.Tool]++
		shown++
		p.printf("%s%-8s [%s] %s\n", indent, issueLabel(is.Level), is.Tool, is.Detail)
	}
	for _, tool := range hiddenOrder {
		shown++
		p.printf("%s%-8s [%s] (+%d more %s findings; rerun with --cli or see the JSON report)\n",
			indent, issueLabel(hiddenLevel[tool]), tool, hidden[tool], tool)
	}
	return shown
}

// issueLabel is the column shown for a check entry. An entry with no
// level set is labeled WARNING, matching how it is counted.
func issueLabel(l checks.Level) string {
	switch l {
	case checks.LevelSecurity:
		return "SECURITY"
	case checks.LevelIssue:
		return "ISSUE"
	default:
		return "WARNING"
	}
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
