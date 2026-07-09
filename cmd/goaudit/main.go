// Command goaudit audits a Go project's dependency graph against
// known-malicious module lists (IOCs) and typosquat heuristics, for use
// locally or as a CI gate.
//
// The threat feed (Socket's PolinRider campaign list) is built in and
// refreshed automatically whenever the cached copy is older than 24 hours.
// Feed problems never abort a scan; they surface as warnings in the report.
//
// Every run writes both formats: the text report to stdout and a JSON
// report file into the scanned directory.
//
// Exit codes: 0 clean, 1 flagged (malicious) match, 2 security findings
// from gosec/govulncheck (always) or warnings/lint issues (with
// --fail-on-warn), 3 operational error.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/thesimpledev/goaudit/internal/checks"
	"github.com/thesimpledev/goaudit/internal/feed"
	"github.com/thesimpledev/goaudit/internal/ioc"
	"github.com/thesimpledev/goaudit/internal/match"
	"github.com/thesimpledev/goaudit/internal/modgraph"
	"github.com/thesimpledev/goaudit/internal/report"
)

// Exit codes for CI use.
const (
	exitClean    = 0
	exitFlagged  = 1
	exitWarnings = 2
	exitError    = 3
)

// defaultFeedURL is Socket's public CSV of packages in the PolinRider
// supply chain attack campaign. Overridable via GOAUDIT_FEED_URL (used by
// tests and useful if the endpoint ever moves).
const defaultFeedURL = "https://socket.dev/api/public/supply-chain-attacks/polinrider/packages.csv"

// cacheTTL is how long a downloaded feed stays fresh before the next run
// re-downloads it.
const cacheTTL = 24 * time.Hour

// jsonReportName is the JSON report file written into the scanned
// directory on every run.
const jsonReportName = "goaudit-report.json"

// localIOCName is the file auto-detected in each project directory.
const localIOCName = ".goaudit-ioc.json"

type options struct {
	path       string
	localIOC   string
	recursive  bool
	failOnWarn bool
	verbose    bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// printf writes a diagnostic or status line. Write failures on stdout and
// stderr are deliberately ignored: there is nowhere left to report them.
func printf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func run(argv []string, stdout, stderr io.Writer) int {
	opts, code, ok := parseFlags(argv, stderr)
	if !ok {
		return code
	}
	a, err := newApp(opts, stdout, stderr)
	if err != nil {
		printf(stderr, "goaudit: %v\n", err)
		return exitError
	}
	ctx := context.Background()
	if opts.recursive || !hasGoMod(a.projectDir) {
		return a.scanMulti(ctx)
	}
	return a.scan(ctx)
}

// parseFlags parses argv into options. When ok is false the returned code
// is the process exit code.
func parseFlags(argv []string, stderr io.Writer) (opts options, code int, ok bool) {
	fs := flag.NewFlagSet("goaudit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.path, "path", ".", "project directory, or a parent directory of many projects")
	fs.StringVar(&opts.localIOC, "local-ioc", "", "extra IOC file applied to every scanned project (each project's "+localIOCName+" is always auto-detected)")
	fs.BoolVar(&opts.recursive, "recursive", false, "scan every Go project found under --path (automatic when --path has no go.mod)")
	fs.BoolVar(&opts.failOnWarn, "fail-on-warn", false, "exit 2 when warnings are found")
	fs.BoolVar(&opts.verbose, "verbose", false, "include clean modules in the report")
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opts, exitClean, false
		}
		return opts, exitError, false
	}
	return opts, exitClean, true
}

// app holds everything one invocation needs, so the command's stages stay
// small.
type app struct {
	opts       options
	projectDir string
	feedURL    string
	client     *feed.Client
	cache      *feed.Cache
	stdout     io.Writer
	stderr     io.Writer
	prog       *progress
}

func newApp(opts options, stdout, stderr io.Writer) (*app, error) {
	projectDir, err := filepath.Abs(opts.path)
	if err != nil {
		return nil, err
	}
	cacheDir := os.Getenv("GOAUDIT_CACHE_DIR")
	if cacheDir == "" {
		cacheDir, err = feed.DefaultDir()
		if err != nil {
			return nil, err
		}
	}
	feedURL := os.Getenv("GOAUDIT_FEED_URL")
	if feedURL == "" {
		feedURL = defaultFeedURL
	}
	return &app{
		opts:       opts,
		projectDir: projectDir,
		feedURL:    feedURL,
		client:     &feed.Client{},
		cache:      &feed.Cache{Dir: cacheDir},
		stdout:     stdout,
		stderr:     stderr,
		prog:       newProgress(stderr),
	}, nil
}

// fail reports an operational error and returns the matching exit code.
func (a *app) fail(err error) int {
	printf(a.stderr, "goaudit: %v\n", err)
	return exitError
}

// scan runs a single-project audit: load IOC sources, list the module
// graph, match, and write both reports.
func (a *app) scan(ctx context.Context) int {
	a.prog.announce("auditing " + a.projectDir + "…")
	base, notes, err := a.loadBaseIOCs(ctx)
	if err != nil {
		return a.fail(err)
	}
	set, localNote, err := withProjectIOCs(base, a.projectDir)
	if err != nil {
		return a.fail(err)
	}
	if localNote != "" {
		notes = append(notes, localNote)
	}
	if set.Len() == 0 {
		notes = append(notes, "no IOC entries loaded; running typosquat heuristics only")
	}
	mods, err := modgraph.List(ctx, a.projectDir)
	if err != nil {
		return a.fail(err)
	}

	findings, _ := buildFindings(mods, match.NewEngine(set))
	issues, checkNotes := runChecks(ctx, a.projectDir)
	notes = append(notes, checkNotes...)
	rep := report.New(a.projectDir, set.Len(), notes, findings, issues)
	a.prog.finish()
	if err := a.writeReports(rep.WriteText, rep.WriteJSON); err != nil {
		return a.fail(fmt.Errorf("write report: %w", err))
	}

	flagged, warnings, _ := rep.Counts()
	security, issueCount := rep.IssueCounts()
	return exitFor(flagged, security, warnings+issueCount, a.opts.failOnWarn)
}

// exitFor folds counts into the process exit code. A malicious match
// dominates; security findings (gosec, govulncheck) always fail the run;
// warnings, lint/test issues, and unscannable projects fail only with
// --fail-on-warn.
func exitFor(flagged, security, soft int, failOnWarn bool) int {
	switch {
	case flagged > 0:
		return exitFlagged
	case security > 0:
		return exitWarnings
	case soft > 0 && failOnWarn:
		return exitWarnings
	default:
		return exitClean
	}
}

// runChecks executes the standard tool suite (vet, staticcheck, errcheck,
// revive, gosec, govulncheck, go test, gofmt -l) against one project.
// GOAUDIT_SKIP_CHECKS disables it (used by tests).
func runChecks(ctx context.Context, dir string) ([]checks.Issue, []string) {
	if os.Getenv("GOAUDIT_SKIP_CHECKS") != "" {
		return nil, nil
	}
	return checks.Run(ctx, dir, checks.DefaultTools())
}

// writeReports emits both formats every run: text to stdout and JSON to a
// file in the scanned directory. A JSON write failure (read-only tree, no
// permission) is reported as a warning, never as a run failure — the exit
// code must stay driven by what the audit found.
func (a *app) writeReports(text, json func(io.Writer, bool) error) error {
	if err := text(a.stdout, a.opts.verbose); err != nil {
		return err
	}
	path := filepath.Join(a.projectDir, jsonReportName)
	if err := writeJSONFile(path, json, a.opts.verbose); err != nil {
		printf(a.stderr, "goaudit: WARNING: could not write %s: %v\n", path, err)
		return nil
	}
	printf(a.stdout, "\njson report written to %s\n", path)
	return nil
}

func writeJSONFile(path string, write func(io.Writer, bool) error, verbose bool) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the report lands in the user-chosen scan directory
	if err != nil {
		return err
	}
	werr := write(f, verbose)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// buildFindings audits every non-main module and returns the findings plus
// the main module's path.
func buildFindings(mods []modgraph.Module, engine *match.Engine) ([]match.Finding, string) {
	var findings []match.Finding
	mainPath := ""
	for _, m := range mods {
		if m.Main {
			mainPath = m.Path
			continue
		}
		findings = append(findings, engine.CheckModule(m))
	}
	return findings, mainPath
}

// loadBaseIOCs loads the IOC sources shared by every project in the run:
// the built-in feed plus the explicit --local-ioc file. Feed problems are
// returned as warning notes, never as errors.
func (a *app) loadBaseIOCs(ctx context.Context) (*ioc.Set, []string, error) {
	set := ioc.NewSet()
	feedSet, notes := a.loadFeedSet(ctx, time.Now())
	set.Merge(feedSet)

	if a.opts.localIOC != "" {
		localSet, localNote, err := loadLocalSet(a.opts.localIOC, "")
		if err != nil {
			return nil, nil, err
		}
		notes = append(notes, localNote)
		set.Merge(localSet)
	}
	return set, notes, nil
}

// withProjectIOCs layers a project's auto-detected IOC file on top of the
// shared base set, leaving the base untouched.
func withProjectIOCs(base *ioc.Set, dir string) (*ioc.Set, string, error) {
	localSet, note, err := loadLocalSet("", dir)
	if err != nil || localSet == nil {
		return base, "", err
	}
	merged := ioc.NewSet()
	merged.Merge(base)
	merged.Merge(localSet)
	return merged, note, nil
}

// loadFeedSet returns the feed-based IOC set. The cached copy is used
// while younger than cacheTTL; otherwise the feed is re-downloaded. Any
// failure falls back to the stale cache (or to no feed data at all) with a
// warning note — a broken feed never stops the scan.
func (a *app) loadFeedSet(ctx context.Context, now time.Time) (*ioc.Set, []string) {
	data, meta := a.cache.Load()
	cacheMatches := data != nil && meta.URL == a.feedURL

	if cacheMatches && meta.Fresh(cacheTTL, now) {
		if set, err := ioc.Parse(data, a.feedURL); err == nil {
			return set, []string{fmt.Sprintf("feed cache fresh (%s old)", meta.Age(now))}
		}
		// An unreadable cache falls through to a refetch.
	}

	etag := ""
	if cacheMatches {
		etag = meta.ETag
	}
	a.prog.announce("refreshing threat feed…")
	res, err := a.client.Fetch(ctx, a.feedURL, etag)
	if err != nil {
		return a.staleFeedFallback(data, meta, err, now)
	}
	if res.NotModified && cacheMatches {
		return a.notModifiedFeedSet(data, meta, etag, now)
	}
	set, err := ioc.Parse(res.Data, a.feedURL)
	if err != nil {
		return a.staleFeedFallback(data, meta, fmt.Errorf("downloaded feed is not usable: %w", err), now)
	}
	if err := a.cache.Store(res.Data, feed.Meta{URL: a.feedURL, ETag: res.ETag, FetchedAt: now}); err != nil {
		return set, []string{fmt.Sprintf("feed refreshed: %d Go entries (WARNING: cache write failed: %v)", set.Len(), err)}
	}
	return set, []string{fmt.Sprintf("feed refreshed: %d Go entries", set.Len())}
}

// staleFeedFallback serves the stale cached feed after a download failure,
// or no feed data at all, always with a warning note.
func (a *app) staleFeedFallback(data []byte, meta *feed.Meta, cause error, now time.Time) (*ioc.Set, []string) {
	if data != nil && meta.URL == a.feedURL {
		if set, err := ioc.Parse(data, a.feedURL); err == nil {
			return set, []string{fmt.Sprintf("WARNING: feed download failed (%v); using cached feed from %s ago", cause, meta.Age(now))}
		}
	}
	return nil, []string{fmt.Sprintf("WARNING: feed download failed (%v); no usable cached copy — scanning with local IOC files and typosquat heuristics only", cause)}
}

// notModifiedFeedSet keeps serving the cache after a 304 response and bumps
// the cache timestamp.
func (a *app) notModifiedFeedSet(data []byte, meta *feed.Meta, etag string, now time.Time) (*ioc.Set, []string) {
	set, err := ioc.Parse(data, a.feedURL)
	if err != nil {
		return a.staleFeedFallback(nil, nil, fmt.Errorf("cached feed is unreadable: %w", err), now)
	}
	note := "feed unchanged (304); using cache"
	if werr := a.cache.WriteMeta(feed.Meta{URL: a.feedURL, ETag: etag, FetchedAt: now}); werr != nil {
		note += " (WARNING: cache timestamp update failed: " + werr.Error() + ")"
	}
	return set, []string{note}
}

// loadLocalSet reads a local IOC file. An explicitly given path must
// exist; the auto-detected per-project file is optional.
func loadLocalSet(explicit, projectDir string) (*ioc.Set, string, error) {
	path := explicit
	if path == "" {
		candidate := filepath.Join(projectDir, localIOCName)
		if _, err := os.Stat(candidate); err != nil {
			return nil, "", nil
		}
		path = candidate
	}
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- the IOC file path comes from the user's own flag or project dir
	if err != nil {
		return nil, "", fmt.Errorf("read local IOC file: %w", err)
	}
	set, err := ioc.Parse(data, path)
	if err != nil {
		return nil, "", fmt.Errorf("parse local IOC file %s: %w", path, err)
	}
	return set, fmt.Sprintf("local IOC file %s: %d entries", path, set.Len()), nil
}
