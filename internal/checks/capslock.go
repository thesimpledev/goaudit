package checks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// capslockBaselineName is the per-project capability baseline file,
// recorded on the first capslock run and diffed against afterwards.
const capslockBaselineName = ".goaudit-capslock.json"

// capslockTimeout bounds one capslock invocation; whole-program analysis
// of a large module can otherwise run for a very long time.
const capslockTimeout = 5 * time.Minute

// capslockBaselineVersion is the schema version written to baselines. A
// baseline with any other version is re-recorded.
const capslockBaselineVersion = 1

// highRiskCapabilities are the capability classes whose appearance in a
// dependency is a security signal: each one gives code a way to run
// commands, reach the network, or escape Go's type safety.
var highRiskCapabilities = map[string]bool{
	"EXEC":                true,
	"NETWORK":             true,
	"SYSTEM_CALLS":        true,
	"ARBITRARY_EXECUTION": true,
	"CGO":                 true,
	"UNSAFE_POINTER":      true,
}

// ignoredCapabilities are capslock's "could not tell" buckets. Diffing
// them produces analyzer noise, not signal.
var ignoredCapabilities = map[string]bool{
	"UNANALYZED":  true,
	"SAFE":        true,
	"UNSPECIFIED": true,
}

// capslockBaseline is the schema of .goaudit-capslock.json. Capabilities
// maps package import paths to sorted capability names (CAPABILITY_ prefix
// stripped); sorted keys and values keep the file stable across runs so it
// diffs cleanly in git.
type capslockBaseline struct {
	Version         int                 `json:"version"`
	CreatedAt       time.Time           `json:"created_at"`
	CapslockVersion string              `json:"capslock_version,omitempty"`
	GOOS            string              `json:"goos"`
	GOARCH          string              `json:"goarch"`
	GoSumSHA256     string              `json:"gosum_sha256"`
	Capabilities    map[string][]string `json:"capabilities"`
}

// Capslock runs Google's capslock capability analyzer against dir with a
// per-project baseline. The first run records the baseline file and
// reports the high-risk capabilities already present; later runs report
// only capabilities gained since the baseline (the "dependency update
// suddenly opens network connections" signal) and are skipped entirely
// while go.sum is unchanged. updateBaseline re-records the baseline,
// accepting the current capabilities. Every failure degrades to a note —
// capslock can never abort or fail a scan on its own error.
func Capslock(ctx context.Context, dir string, updateBaseline bool) ([]Issue, []string) {
	bin, err := exec.LookPath("capslock")
	if err != nil {
		return nil, []string{"capslock not installed; skipped"}
	}

	var notes []string
	baseline, berr := loadCapslockBaseline(dir)
	if berr != nil {
		notes = append(notes, "capslock: existing baseline unusable ("+berr.Error()+"); re-recording")
		baseline = nil
	}
	env := capslockEnv{bin: bin, gosum: gosumSHA256(dir)}
	if baseline != nil && !updateBaseline && baseline.GoSumSHA256 == env.gosum {
		return nil, append(notes, "capslock: dependencies unchanged since baseline; skipped")
	}

	// Replay the baseline's platform so diffs compare like with like even
	// when the baseline was recorded on another machine.
	env.goos, env.goarch = runtime.GOOS, runtime.GOARCH
	if baseline != nil && baseline.GOOS != "" {
		env.goos, env.goarch = baseline.GOOS, baseline.GOARCH
	}
	current, err := runCapslock(ctx, dir, env.goos, env.goarch)
	if err != nil {
		return nil, append(notes, "capslock: "+err.Error()+"; skipped")
	}

	if baseline == nil || updateBaseline {
		notes = append(notes, recordBaseline(dir, env, current))
		return firstRunIssues(current), notes
	}
	return diffRun(dir, env, baseline, current, notes)
}

// capslockEnv carries the run's fixed inputs: the analyzer binary, the
// project's go.sum fingerprint, and the platform the baseline is pinned to.
type capslockEnv struct {
	bin    string
	gosum  string
	goos   string
	goarch string
}

// diffRun compares the current capabilities against the baseline and
// reports what was gained. The baseline is not updated after a gain is
// reported — the alert has to repeat until the user accepts it — except
// when the diff is empty, where refreshing silences nothing and restores
// the go.sum fast path.
func diffRun(dir string, env capslockEnv, baseline *capslockBaseline, current map[string]map[string]string, notes []string) ([]Issue, []string) {
	gains, lost := diffCapabilities(baseline.Capabilities, current)
	if len(gains) == 0 {
		note := "capslock: dependencies changed but capabilities did not; baseline refreshed"
		if lost > 0 {
			note += fmt.Sprintf(" (%d capabilities no longer present)", lost)
		}
		notes = append(notes, note)
		if warn := refreshNote(recordBaseline(dir, env, current)); warn != "" {
			notes = append(notes, warn)
		}
		return nil, notes
	}

	if lost > 0 {
		notes = append(notes, fmt.Sprintf("capslock: %d baseline capabilities no longer present; --update-baselines refreshes the baseline", lost))
	}
	if v := capslockVersion(env.bin); baseline.CapslockVersion != "" && v != "" && v != baseline.CapslockVersion {
		notes = append(notes, fmt.Sprintf("capslock: analyzer upgraded since the baseline (%s → %s); some gains may come from the upgrade, not your dependencies", baseline.CapslockVersion, v))
	}
	return gainIssues(gains), notes
}

// refreshNote keeps only the failure half of a recordBaseline note: on a
// silent refresh the success message would be duplicate noise.
func refreshNote(note string) string {
	if strings.Contains(note, "WARNING") {
		return note
	}
	return ""
}

// runCapslock executes the analyzer and reduces its JSON to package →
// capability → example call path.
func runCapslock(ctx context.Context, dir, goos, goarch string) (map[string]map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, capslockTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "capslock", "-packages=./...", "-output=json", "-goos="+goos, "-goarch="+goarch) // #nosec G204 -- fixed binary and flags; goos/goarch come from the Go runtime or the project's own baseline file
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("timed out after %s", capslockTimeout)
		}
		return nil, fmt.Errorf("failed: %s", firstNonEmptyLine(stderr.Bytes(), stdout.Bytes()))
	}
	caps, err := parseCapslockOutput(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("could not parse output: %v", err)
	}
	return caps, nil
}

// capslockOutput mirrors the fields of capslock's protojson output that
// the audit needs. packageDir carries the package import path.
type capslockOutput struct {
	CapabilityInfo []capslockCapability `json:"capabilityInfo"`
}

type capslockCapability struct {
	Capability string         `json:"capability"`
	PackageDir string         `json:"packageDir"`
	Path       []capslockFunc `json:"path"`
}

type capslockFunc struct {
	Name string `json:"name"`
}

func parseCapslockOutput(raw []byte) (map[string]map[string]string, error) {
	var out capslockOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	caps := make(map[string]map[string]string)
	for _, ci := range out.CapabilityInfo {
		name := strings.TrimPrefix(ci.Capability, "CAPABILITY_")
		if ci.PackageDir == "" || name == "" {
			continue
		}
		if caps[ci.PackageDir] == nil {
			caps[ci.PackageDir] = make(map[string]string)
		}
		if _, seen := caps[ci.PackageDir][name]; !seen {
			caps[ci.PackageDir][name] = capslockVia(ci.Path)
		}
	}
	return caps, nil
}

// capslockVia names the deepest call in the example path — the function
// actually responsible for the capability.
func capslockVia(path []capslockFunc) string {
	if len(path) == 0 {
		return ""
	}
	return path[len(path)-1].Name
}

// firstRunIssues lists the high-risk capabilities present when a baseline
// is recorded: an inventory, not an incident, so never Security.
func firstRunIssues(current map[string]map[string]string) []Issue {
	var issues []Issue
	for _, pkg := range sortedCapKeys(current) {
		for _, name := range sortedCapKeys(current[pkg]) {
			if !highRiskCapabilities[name] {
				continue
			}
			issues = append(issues, Issue{Tool: "capslock", Detail: capslockDetail(pkg, "uses", name, current[pkg][name])})
		}
	}
	return issues
}

type capGain struct {
	pkg        string
	capability string
	via        string
}

// diffCapabilities returns the capabilities present now but absent from
// the baseline, high-risk first, plus a count of baseline capabilities no
// longer present.
func diffCapabilities(old map[string][]string, current map[string]map[string]string) (gains []capGain, lost int) {
	return gainedCapabilities(old, current), lostCount(old, current)
}

func gainedCapabilities(old map[string][]string, current map[string]map[string]string) []capGain {
	oldSet := make(map[string]map[string]bool, len(old))
	for pkg, names := range old {
		oldSet[pkg] = make(map[string]bool, len(names))
		for _, n := range names {
			oldSet[pkg][n] = true
		}
	}
	var gains []capGain
	for _, pkg := range sortedCapKeys(current) {
		for _, name := range sortedCapKeys(current[pkg]) {
			if ignoredCapabilities[name] || oldSet[pkg][name] {
				continue
			}
			gains = append(gains, capGain{pkg: pkg, capability: name, via: current[pkg][name]})
		}
	}
	sort.SliceStable(gains, func(i, j int) bool {
		return highRiskCapabilities[gains[i].capability] && !highRiskCapabilities[gains[j].capability]
	})
	return gains
}

func lostCount(old map[string][]string, current map[string]map[string]string) int {
	lost := 0
	for pkg, names := range old {
		for _, n := range names {
			if ignoredCapabilities[n] {
				continue
			}
			if _, ok := current[pkg][n]; !ok {
				lost++
			}
		}
	}
	return lost
}

// gainIssues reports each gained capability; a gained high-risk capability
// is the worm signal and marks the run as a security finding.
func gainIssues(gains []capGain) []Issue {
	issues := make([]Issue, 0, len(gains))
	for _, g := range gains {
		issues = append(issues, Issue{
			Tool:     "capslock",
			Detail:   capslockDetail(g.pkg, "gained", g.capability, g.via) + " since baseline",
			Security: highRiskCapabilities[g.capability],
		})
	}
	return issues
}

func capslockDetail(pkg, verb, capability, via string) string {
	detail := fmt.Sprintf("%s %s %s", pkg, verb, capability)
	if via != "" {
		detail += " (via " + via + ")"
	}
	return detail
}

// recordBaseline writes the baseline file, returning the note to surface.
// A write failure degrades to a warning, mirroring the report writer.
func recordBaseline(dir string, env capslockEnv, current map[string]map[string]string) string {
	b := &capslockBaseline{
		Version:         capslockBaselineVersion,
		CreatedAt:       time.Now().UTC(),
		CapslockVersion: capslockVersion(env.bin),
		GOOS:            env.goos,
		GOARCH:          env.goarch,
		GoSumSHA256:     env.gosum,
		Capabilities:    make(map[string][]string, len(current)),
	}
	for pkg, names := range current {
		b.Capabilities[pkg] = sortedCapKeys(names)
	}
	path := filepath.Join(dir, capslockBaselineName)
	raw, err := json.MarshalIndent(b, "", "  ")
	if err == nil {
		err = os.WriteFile(path, append(raw, '\n'), 0o600)
	}
	if err != nil {
		return "capslock: WARNING: could not write baseline " + path + ": " + err.Error()
	}
	return "capslock: baseline recorded at " + path + "; commit it to lock in current capabilities"
}

// loadCapslockBaseline returns nil, nil when no baseline exists; any other
// problem (unreadable, unparseable, unknown version) is an error the
// caller reports before re-recording.
func loadCapslockBaseline(dir string) (*capslockBaseline, error) {
	raw, err := os.ReadFile(filepath.Join(dir, capslockBaselineName)) // #nosec G304 -- the baseline lives in the user-chosen scan directory
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var b capslockBaseline
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	if b.Version != capslockBaselineVersion {
		return nil, fmt.Errorf("unsupported baseline version %d", b.Version)
	}
	return &b, nil
}

// gosumSHA256 fingerprints the project's dependency set. A project with no
// go.sum hashes as empty input, which still compares correctly.
func gosumSHA256(dir string) string {
	data, _ := os.ReadFile(filepath.Join(dir, "go.sum")) // #nosec G304 -- read from the user-chosen scan directory
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// capslockVersion reports the analyzer's module version, best effort.
func capslockVersion(bin string) string {
	out, err := exec.Command("go", "version", "-m", bin).Output() // #nosec G204 -- bin comes from exec.LookPath("capslock")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "mod" && strings.HasSuffix(fields[1], "/capslock") {
			return fields[2]
		}
	}
	return ""
}

func sortedCapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
