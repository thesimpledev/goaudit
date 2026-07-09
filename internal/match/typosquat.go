package match

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	majorSuffixRE = regexp.MustCompile(`/v[0-9]+$`)
	gopkgSuffixRE = regexp.MustCompile(`\.v[0-9]+$`)
)

// normalizePath strips major-version suffixes ("/v2" everywhere, ".v2" on
// gopkg.in paths) so different major versions of one module compare as the
// same path.
func normalizePath(p string) string {
	p = strings.TrimSuffix(strings.TrimSpace(p), "/")
	p = majorSuffixRE.ReplaceAllString(p, "")
	if strings.HasPrefix(p, "gopkg.in/") {
		p = gopkgSuffixRE.ReplaceAllString(p, "")
	}
	return p
}

// distanceThreshold returns how many edits away from a popular path still
// counts as suspicious. Short paths get a tighter bound to limit false
// positives.
func distanceThreshold(popular string) int {
	if len(popular) <= 15 {
		return 1
	}
	return 2
}

// typosquat reports whether path looks like an imitation of a popular
// module: either within a small edit distance of one, or reusing a popular
// module's name under a different owner on the same host. Paths that are
// themselves in the popular corpus are never reported.
func (e *Engine) typosquat(path string) (rule, detail string, ok bool) {
	norm := normalizePath(path)
	if _, known := e.popSet[norm]; known {
		return "", "", false
	}
	for _, pop := range e.popular {
		d := Distance(norm, pop)
		if d > 0 && d <= distanceThreshold(pop) {
			return "typosquat", fmt.Sprintf("path is %d edit(s) away from popular module %s", d, pop), true
		}
	}
	if detail, found := e.ownerMismatch(norm); found {
		return "owner-mismatch", detail, true
	}
	return "", "", false
}

// ownerMismatch looks for a popular module with the same host and final
// segment whose owner name path looks imitated.
func (e *Engine) ownerMismatch(norm string) (string, bool) {
	segs := strings.Split(norm, "/")
	if len(segs) < 3 {
		return "", false
	}
	host, owner, name := segs[0], segs[1], segs[len(segs)-1]
	for _, pop := range e.popular {
		ps := strings.Split(pop, "/")
		if len(ps) < 3 || ps[0] != host || ps[len(ps)-1] != name {
			continue
		}
		if owner != ps[1] && ownerImitates(owner, ps[1]) {
			return fmt.Sprintf("owner looks like an imitation of popular module %s", pop), true
		}
	}
	return "", false
}

// ownerImitates reports whether one owner name looks like a dressed-up
// version of the other (e.g. "gorilla-io" imitating "gorilla", or a
// case-swap like "Sirupsen"). Unrelated owners publishing same-named
// repos is normal on GitHub and is not reported — that was the source of
// nearly all false positives.
func ownerImitates(owner, popOwner string) bool {
	a := strings.ToLower(owner)
	b := strings.ToLower(popOwner)
	if len(a) < 4 || len(b) < 4 {
		return false
	}
	return strings.Contains(a, b) || strings.Contains(b, a)
}

// parseCorpus loads the embedded popular-modules list: one path per line,
// blank lines and # comments ignored, normalized and deduplicated.
func parseCorpus(raw string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		norm := normalizePath(line)
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	return out
}
