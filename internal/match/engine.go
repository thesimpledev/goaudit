// Package match compares a project's modules against IOC entries and
// typosquat heuristics.
package match

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"github.com/thesimpledev/goaudit/internal/ioc"
	"github.com/thesimpledev/goaudit/internal/modgraph"
)

// Status classifies a finding. Higher values are worse.
type Status int

// Finding statuses, from benign to malicious.
const (
	Clean Status = iota
	Warning
	Flagged
)

// String returns the lowercase name of the status.
func (s Status) String() string {
	switch s {
	case Flagged:
		return "flagged"
	case Warning:
		return "warning"
	default:
		return "clean"
	}
}

// Finding is the audit result for a single module.
type Finding struct {
	Module  string
	Version string
	Status  Status
	Rule    string
	Detail  string
}

//go:embed popular_modules.txt
var popularRaw string

// Engine checks modules against an IOC set and a corpus of popular Go
// module paths used for typosquat detection.
type Engine struct {
	iocs    *ioc.Set
	popular []string
	popSet  map[string]struct{}
}

// loadCorpus parses the embedded popular-modules list once per process,
// so building an engine per project stays cheap in multi-project scans.
var loadCorpus = sync.OnceValues(func() ([]string, map[string]struct{}) {
	popular := parseCorpus(popularRaw)
	popSet := make(map[string]struct{}, len(popular))
	for _, p := range popular {
		popSet[p] = struct{}{}
	}
	return popular, popSet
})

// NewEngine builds an Engine around the given IOC set.
func NewEngine(iocs *ioc.Set) *Engine {
	popular, popSet := loadCorpus()
	return &Engine{iocs: iocs, popular: popular, popSet: popSet}
}

// CheckModule audits one module. When the module is replaced by another
// module, the replacement is audited too and the worse result wins;
// filesystem replaces (no version) are skipped.
func (e *Engine) CheckModule(m modgraph.Module) Finding {
	f := e.check(m.Path, m.Version)
	if m.Replace != nil && m.Replace.Version != "" {
		rf := e.check(m.Replace.Path, m.Replace.Version)
		if rf.Status > f.Status {
			rf.Detail = fmt.Sprintf("via replace %s@%s: %s", m.Replace.Path, m.Replace.Version, rf.Detail)
			rf.Module = m.Path
			rf.Version = m.Version
			f = rf
		}
	}
	return f
}

func (e *Engine) check(path, version string) Finding {
	f := Finding{Module: path, Version: version, Status: Clean}
	if e.iocs.Allowed(path) {
		f.Rule = "allowlist"
		f.Detail = "module is on the allowlist"
		return f
	}
	for _, entry := range e.iocs.Lookup(path) {
		if entry.MatchVersion(version) {
			f.Status = Flagged
			f.Rule = "ioc"
			f.Detail = iocDetail(entry)
			return f
		}
		f.Status = Warning
		f.Rule = "ioc-module"
		f.Detail = fmt.Sprintf("module is in the IOC list (bad versions: %s) but this version is not listed",
			strings.Join(entry.Versions, ", "))
	}
	if f.Status != Clean {
		return f
	}
	if rule, detail, ok := e.typosquat(path); ok {
		f.Status = Warning
		f.Rule = rule
		f.Detail = detail
	}
	return f
}

func iocDetail(entry ioc.Entry) string {
	detail := "exact match in IOC list"
	if entry.Campaign != "" {
		detail += " (campaign: " + entry.Campaign + ")"
	}
	if entry.Reason != "" {
		detail += ": " + entry.Reason
	}
	if entry.Source != "" {
		detail += " [" + entry.Source + "]"
	}
	return detail
}
