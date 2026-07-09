package checks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// parseGosec reads gosec's JSON report and emits one issue per finding.
func parseGosec(dir string, stdout, stderr []byte, exitCode int) []Issue {
	var report struct {
		Issues []struct {
			Severity string `json:"severity"`
			RuleID   string `json:"rule_id"`
			Details  string `json:"details"`
			File     string `json:"file"`
			Line     string `json:"line"`
		} `json:"Issues"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &report); err != nil {
		if exitCode == 0 {
			return nil
		}
		return []Issue{{Tool: "gosec", Detail: firstNonEmptyLine(stderr, stdout)}}
	}
	var issues []Issue
	for _, gi := range report.Issues {
		file := strings.TrimPrefix(strings.TrimPrefix(gi.File, dir), "/")
		issues = append(issues, Issue{
			Tool:     "gosec",
			Detail:   fmt.Sprintf("%s (%s): %s [%s:%s]", gi.RuleID, gi.Severity, gi.Details, file, gi.Line),
			Security: true,
		})
	}
	return issues
}

// vulnInfo accumulates what the govulncheck stream reveals about one OSV
// entry across its module/package/symbol-level findings.
type vulnInfo struct {
	id, summary            string
	module, version, fixed string
	called                 bool
}

// parseGovulncheck reads govulncheck's JSON stream and emits one issue per
// vulnerability whose vulnerable symbol is actually reached by the
// project's code — the same standard the plain govulncheck run applies
// when deciding its exit code.
func parseGovulncheck(_ string, stdout, stderr []byte, exitCode int) []Issue {
	var issues []Issue
	for _, v := range decodeGovulncheck(stdout) {
		if !v.called {
			continue
		}
		detail := fmt.Sprintf("%s: %s (%s@%s", v.id, v.summary, v.module, v.version)
		if v.fixed != "" {
			detail += ", fixed in " + v.fixed
		}
		detail += ")"
		issues = append(issues, Issue{Tool: "govulncheck", Detail: detail, Security: true})
	}
	if len(issues) == 0 && exitCode != 0 && len(bytes.TrimSpace(stdout)) == 0 {
		return []Issue{{Tool: "govulncheck", Detail: firstNonEmptyLine(stderr)}}
	}
	return issues
}

// decodeGovulncheck folds the message stream into one record per OSV id,
// in first-seen order. A truncated stream yields what was parsed so far.
func decodeGovulncheck(stdout []byte) []*vulnInfo {
	type frame struct {
		Module   string `json:"module"`
		Version  string `json:"version"`
		Function string `json:"function"`
	}
	type message struct {
		OSV *struct {
			ID      string `json:"id"`
			Summary string `json:"summary"`
		} `json:"osv"`
		Finding *struct {
			OSV          string  `json:"osv"`
			FixedVersion string  `json:"fixed_version"`
			Trace        []frame `json:"trace"`
		} `json:"finding"`
	}

	summaries := make(map[string]string)
	vulns := make(map[string]*vulnInfo)
	var order []*vulnInfo

	dec := json.NewDecoder(bytes.NewReader(stdout))
	for {
		var m message
		if err := dec.Decode(&m); err != nil {
			break // io.EOF ends the stream; anything else truncates it
		}
		if m.OSV != nil {
			summaries[m.OSV.ID] = m.OSV.Summary
			continue
		}
		if m.Finding == nil || len(m.Finding.Trace) == 0 {
			continue
		}
		v := vulns[m.Finding.OSV]
		if v == nil {
			v = &vulnInfo{id: m.Finding.OSV}
			vulns[m.Finding.OSV] = v
			order = append(order, v)
		}
		first := m.Finding.Trace[0]
		mergeFrame(v, first.Module, first.Version, first.Function, m.Finding.FixedVersion)
	}
	for _, v := range order {
		v.summary = summaries[v.id]
	}
	return order
}

func mergeFrame(v *vulnInfo, module, version, function, fixed string) {
	if module != "" {
		v.module = module
	}
	if version != "" {
		v.version = version
	}
	if fixed != "" {
		v.fixed = fixed
	}
	if function != "" {
		v.called = true
	}
}
