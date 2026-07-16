// Command goaudit audits a Go project's dependency graph against
// known-malicious module lists (IOCs) and typosquat heuristics, for use
// locally or as a CI gate.
//
// Two threat feeds are built in and refreshed automatically whenever the
// cached copy is older than 24 hours: Socket's PolinRider campaign list and
// the OpenSSF malicious-packages database (the MAL- records of OSV.dev's Go
// ecosystem export). Feed problems never abort a scan; they surface as
// warnings in the report.
//
// Every run writes both formats: the text report to stdout and a JSON
// report file into the scanned directory.
//
// Exit codes: 0 clean, 1 flagged (malicious) match, 2 security findings
// from gosec/govulncheck (always) or warnings/lint issues (with
// --fail-on-warn), 3 operational error.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
// tests and useful if the endpoint ever moves); the value "off" disables
// the feed.
const defaultFeedURL = "https://socket.dev/api/public/supply-chain-attacks/polinrider/packages.csv"

// defaultOSVFeedURL is OSV.dev's bulk export of the Go ecosystem. Only its
// MAL- members (the OpenSSF malicious-packages reports) are used; the
// vulnerability records are govulncheck's job. Overridable via
// GOAUDIT_OSV_FEED_URL; the value "off" disables the feed.
const defaultOSVFeedURL = "https://storage.googleapis.com/osv-vulnerabilities/Go/all.zip"

// feedOff is the env value that disables a feed.
const feedOff = "off"

// cacheTTL is how long a downloaded feed stays fresh before the next run
// re-downloads it.
const cacheTTL = 24 * time.Hour

// jsonReportName is the JSON report file written into the scanned
// directory on every run.
const jsonReportName = "goaudit-report.json"

// localIOCName is the file auto-detected in each project directory.
const localIOCName = ".goaudit-ioc.json"

type options struct {
	path            string
	localIOC        string
	recursive       bool
	failOnWarn      bool
	verbose         bool
	updateBaselines bool
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
	fs.BoolVar(&opts.updateBaselines, "update-baselines", false, "re-record each project's capslock capability baseline, accepting its current capabilities")
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opts, exitClean, false
		}
		return opts, exitError, false
	}
	return opts, exitClean, true
}

// feedSpec describes one built-in threat feed: where it lives, how its
// cache files are named, and how its payload becomes IOC entries.
type feedSpec struct {
	name  string // human label; prefixes every note about this feed
	key   string // cache file key; "" keeps the legacy feed.data names
	url   string
	parse func(data []byte, source string) (*ioc.Set, error)
}

// app holds everything one invocation needs, so the command's stages stay
// small.
type app struct {
	opts       options
	projectDir string
	feeds      []feedSpec
	client     *feed.Client
	dataDir    string
	stdout     io.Writer
	stderr     io.Writer
	prog       *progress
}

func newApp(opts options, stdout, stderr io.Writer) (*app, error) {
	projectDir, err := filepath.Abs(opts.path)
	if err != nil {
		return nil, err
	}
	dataDir := os.Getenv("GOAUDIT_DATA_DIR")
	if dataDir == "" {
		dataDir = os.Getenv("GOAUDIT_CACHE_DIR") // deprecated name, still honored
	}
	if dataDir == "" {
		dataDir, err = feed.DefaultDir()
		if err != nil {
			return nil, err
		}
	}
	return &app{
		opts:       opts,
		projectDir: projectDir,
		feeds:      builtinFeeds(),
		client:     &feed.Client{},
		dataDir:    dataDir,
		stdout:     stdout,
		stderr:     stderr,
		prog:       newProgress(stderr),
	}, nil
}

// builtinFeeds returns the feed list with env overrides applied.
func builtinFeeds() []feedSpec {
	socketURL := os.Getenv("GOAUDIT_FEED_URL")
	if socketURL == "" {
		socketURL = defaultFeedURL
	}
	osvURL := os.Getenv("GOAUDIT_OSV_FEED_URL")
	if osvURL == "" {
		osvURL = defaultOSVFeedURL
	}
	return []feedSpec{
		{name: "Socket PolinRider feed", key: "", url: socketURL, parse: ioc.Parse},
		{name: "OSV malicious-package feed", key: "osv", url: osvURL, parse: parseOSVZip},
	}
}

// parseOSVZip loads an OSV ecosystem export archive, keeping only the MAL-
// records (the OpenSSF malicious-packages reports). The thousands of
// vulnerability records in the same archive are skipped without being
// decompressed — govulncheck covers those.
func parseOSVZip(data []byte, source string) (*ioc.Set, error) {
	members, err := feed.ExtractZipMembers(data, "MAL-", ".json")
	if err != nil {
		return nil, err
	}
	batch := append([]byte{'['}, bytes.Join(members, []byte{','})...)
	batch = append(batch, ']')
	return ioc.ParseOSV(batch, source)
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
	issues, checkNotes := a.runChecks(ctx, a.projectDir)
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

// runChecks executes the tool suite (vet, gofix, staticcheck, errcheck,
// revive, gosec, govulncheck, go test, gofmt -l, capslock) against one
// project.
// GOAUDIT_SKIP_CHECKS names checks to skip, or disables the whole suite.
func (a *app) runChecks(ctx context.Context, dir string) ([]checks.Issue, []string) {
	skipAll, skip := parseSkipChecks(os.Getenv("GOAUDIT_SKIP_CHECKS"))
	if skipAll {
		return nil, nil
	}
	var tools []checks.Tool
	for _, t := range checks.DefaultTools() {
		if !skip[t.Name] {
			tools = append(tools, t)
		}
	}
	issues, notes := checks.Run(ctx, dir, tools)
	if !skip["capslock"] {
		capsIssues, capsNotes := checks.Capslock(ctx, dir, a.opts.updateBaselines)
		issues = append(issues, capsIssues...)
		notes = append(notes, capsNotes...)
	}
	return issues, notes
}

// parseSkipChecks interprets GOAUDIT_SKIP_CHECKS: empty runs everything; a
// comma-separated list of known check names skips just those (for example
// "capslock" or "test,capslock"); any unknown token — including the
// traditional "1" — skips the whole suite, preserving the original
// any-non-empty-value behavior.
func parseSkipChecks(value string) (skipAll bool, skip map[string]bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, nil
	}
	known := map[string]bool{"capslock": true}
	for _, t := range checks.DefaultTools() {
		known[t.Name] = true
	}
	skip = make(map[string]bool)
	for _, tok := range strings.Split(value, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok == "" {
			continue
		}
		if !known[tok] {
			return true, nil
		}
		skip[tok] = true
	}
	return false, skip
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
// the built-in feeds plus the explicit --local-ioc file. Each feed loads
// and fails independently; feed problems are returned as warning notes,
// never as errors.
func (a *app) loadBaseIOCs(ctx context.Context) (*ioc.Set, []string, error) {
	set := ioc.NewSet()
	var notes []string
	now := time.Now()
	for _, spec := range a.feeds {
		feedSet, feedNotes := a.loadFeedSet(ctx, spec, now)
		set.Merge(feedSet)
		notes = append(notes, feedNotes...)
	}

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

// loadFeedSet returns one feed's IOC set. The cached copy is used while
// younger than cacheTTL; otherwise the feed is re-downloaded. Any failure
// falls back to the stale cache (or to no feed data at all) with a warning
// note — a broken feed never stops the scan.
func (a *app) loadFeedSet(ctx context.Context, spec feedSpec, now time.Time) (*ioc.Set, []string) {
	if spec.url == feedOff {
		return nil, []string{spec.name + " disabled"}
	}
	cache := &feed.Cache{Dir: a.dataDir, Key: spec.key}
	data, meta := cache.Load()
	cacheMatches := data != nil && meta.URL == spec.url

	if cacheMatches && meta.Fresh(cacheTTL, now) {
		if set, err := spec.parse(data, spec.url); err == nil {
			return set, []string{fmt.Sprintf("%s cache fresh (%s old)", spec.name, meta.Age(now))}
		}
		// An unreadable cache falls through to a refetch.
	}

	etag := ""
	if cacheMatches {
		etag = meta.ETag
	}
	a.prog.announce("refreshing " + spec.name + "…")
	res, err := a.client.Fetch(ctx, spec.url, etag)
	if err != nil {
		return a.staleFeedFallback(spec, data, meta, err, now)
	}
	if res.NotModified && cacheMatches {
		return a.notModifiedFeedSet(spec, cache, data, etag, now)
	}
	set, err := spec.parse(res.Data, spec.url)
	if err != nil {
		return a.staleFeedFallback(spec, data, meta, fmt.Errorf("downloaded feed is not usable: %w", err), now)
	}
	if err := cache.Store(res.Data, feed.Meta{URL: spec.url, ETag: res.ETag, FetchedAt: now}); err != nil {
		return set, []string{fmt.Sprintf("%s refreshed: %d Go entries (WARNING: cache write failed: %v)", spec.name, set.Len(), err)}
	}
	return set, []string{fmt.Sprintf("%s refreshed: %d Go entries", spec.name, set.Len())}
}

// staleFeedFallback serves the stale cached feed after a download failure,
// or no feed data at all, always with a warning note.
func (a *app) staleFeedFallback(spec feedSpec, data []byte, meta *feed.Meta, cause error, now time.Time) (*ioc.Set, []string) {
	if data != nil && meta.URL == spec.url {
		if set, err := spec.parse(data, spec.url); err == nil {
			return set, []string{fmt.Sprintf("WARNING: %s download failed (%v); using cached feed from %s ago", spec.name, cause, meta.Age(now))}
		}
	}
	return nil, []string{fmt.Sprintf("WARNING: %s download failed (%v); no usable cached copy — continuing without it", spec.name, cause)}
}

// notModifiedFeedSet keeps serving the cache after a 304 response and bumps
// the cache timestamp.
func (a *app) notModifiedFeedSet(spec feedSpec, cache *feed.Cache, data []byte, etag string, now time.Time) (*ioc.Set, []string) {
	set, err := spec.parse(data, spec.url)
	if err != nil {
		return a.staleFeedFallback(spec, nil, nil, fmt.Errorf("cached feed is unreadable: %w", err), now)
	}
	note := spec.name + " unchanged (304); using cache"
	if werr := cache.WriteMeta(feed.Meta{URL: spec.url, ETag: etag, FetchedAt: now}); werr != nil {
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
