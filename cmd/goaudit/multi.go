package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/thesimpledev/goaudit/internal/ioc"
	"github.com/thesimpledev/goaudit/internal/match"
	"github.com/thesimpledev/goaudit/internal/modgraph"
	"github.com/thesimpledev/goaudit/internal/report"
)

// hasGoMod reports whether dir contains a go.mod file.
func hasGoMod(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "go.mod"))
	return err == nil
}

// scanMulti audits every Go project found under the target directory and
// writes one combined report grouped by project.
func (a *app) scanMulti(ctx context.Context) int {
	dirs, err := modgraph.DiscoverModules(a.projectDir)
	if err != nil {
		return a.fail(err)
	}
	if len(dirs) == 0 {
		return a.fail(fmt.Errorf("no go.mod found under %s", a.projectDir))
	}
	a.prog.setTotal(len(dirs))
	a.prog.announce(fmt.Sprintf("auditing %d projects under %s…", len(dirs), a.projectDir))
	base, notes, err := a.loadBaseIOCs(ctx)
	if err != nil {
		return a.fail(err)
	}
	// A .goaudit-ioc.json at the scan root applies to every project, so
	// allowlist entries can live in one place.
	base, rootNote, err := withProjectIOCs(base, a.projectDir)
	if err != nil {
		return a.fail(err)
	}
	if rootNote != "" {
		notes = append(notes, rootNote)
	}
	if base.Len() == 0 {
		notes = append(notes, "no shared IOC entries loaded; per-project IOC files and typosquat heuristics still apply")
	}
	results := a.scanAll(ctx, dirs, base)
	rep := report.NewMulti(a.projectDir, base.Len(), notes, results)
	a.prog.finish()
	if err := a.writeReports(rep.WriteText, rep.WriteJSON); err != nil {
		return a.fail(fmt.Errorf("write report: %w", err))
	}
	return multiExitCode(rep, a.opts.failOnWarn)
}

// scanAll audits each project with a bounded worker pool. Results keep the
// order of dirs; each worker writes only its own slice slot. The pool is
// smaller than the CPU count because the check suite (staticcheck, gosec,
// go test -race) is itself heavily parallel per project.
func (a *app) scanAll(ctx context.Context, dirs []string, base *ioc.Set) []report.ProjectResult {
	sem := make(chan struct{}, min(4, runtime.NumCPU()))
	results := make([]report.ProjectResult, len(dirs))
	var wg sync.WaitGroup
	for i, dir := range dirs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = a.scanProject(ctx, dir, base)
			a.prog.step(results[i].Name)
		}()
	}
	wg.Wait()
	return results
}

// scanProject audits a single project directory against the shared base
// IOC set plus the project's own IOC file, if present.
func (a *app) scanProject(ctx context.Context, dir string, base *ioc.Set) report.ProjectResult {
	res := report.ProjectResult{Name: filepath.Base(dir), Dir: dir}
	mods, err := modgraph.List(ctx, dir)
	if err != nil {
		res.Err = err
		return res
	}
	set, localNote, err := withProjectIOCs(base, dir)
	if err != nil {
		res.Err = err
		return res
	}
	var notes []string
	if localNote != "" {
		notes = append(notes, localNote)
	}
	findings, modulePath := buildFindings(mods, match.NewEngine(set))
	issues, checkNotes := runChecks(ctx, dir)
	notes = append(notes, checkNotes...)
	res.Name = nameFromModule(modulePath, dir)
	res.Report = report.New(dir, set.Len(), notes, findings, issues)
	return res
}

// multiExitCode folds the combined results into one CI exit code via
// exitFor: malware → 1, security findings → 2 always; warnings, lint/test
// issues, and unscannable projects → 2 only with --fail-on-warn.
func multiExitCode(rep *report.MultiReport, failOnWarn bool) int {
	t := rep.Totals()
	return exitFor(t.Flagged, t.Security, t.Warnings+t.Issues+t.Failed, failOnWarn)
}

// nameFromModule derives a project's display name: everything after the
// host segment of the module path ("github.com/owner/repo" → "owner/repo"),
// or the folder name when the module path is empty or not host-based.
func nameFromModule(modulePath, dir string) string {
	segs := strings.Split(modulePath, "/")
	if modulePath == "" || len(segs) == 1 || !strings.Contains(segs[0], ".") {
		return filepath.Base(dir)
	}
	return strings.Join(segs[1:], "/")
}
