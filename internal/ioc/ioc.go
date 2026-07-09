// Package ioc defines the indicator-of-compromise data model used by the
// audit, along with loaders for JSON and CSV threat feeds.
package ioc

import (
	"bytes"
	"errors"
	"strings"
	"unicode"
)

// Entry describes one known-bad Go module taken from a threat feed or a
// local IOC file. An Entry with no Versions matches every version of the
// module.
type Entry struct {
	Module   string   `json:"module"`
	Versions []string `json:"versions,omitempty"`
	Campaign string   `json:"campaign,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Source   string   `json:"source,omitempty"`
}

// MatchVersion reports whether the entry applies to the given module version.
func (e Entry) MatchVersion(version string) bool {
	if len(e.Versions) == 0 {
		return true
	}
	want := NormalizeVersion(version)
	for _, v := range e.Versions {
		if NormalizeVersion(v) == want {
			return true
		}
	}
	return false
}

// NormalizeVersion strips the leading "v" and any "+incompatible" suffix so
// that versions from feeds and from `go list` compare cleanly.
func NormalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, "+incompatible")
	return strings.TrimPrefix(v, "v")
}

// Set is a collection of IOC entries indexed by module path, plus an
// allowlist of module paths that must never be reported.
type Set struct {
	entries map[string][]Entry
	allow   map[string]struct{}
}

// NewSet returns an empty Set.
func NewSet() *Set {
	return &Set{
		entries: make(map[string][]Entry),
		allow:   make(map[string]struct{}),
	}
}

// Add records an IOC entry. Entries without a module path are ignored.
func (s *Set) Add(e Entry) {
	e.Module = strings.TrimSpace(e.Module)
	if e.Module == "" {
		return
	}
	s.entries[e.Module] = append(s.entries[e.Module], e)
}

// AddAllow marks a module path as trusted so it is never reported.
func (s *Set) AddAllow(path string) {
	path = strings.TrimSpace(path)
	if path != "" {
		s.allow[path] = struct{}{}
	}
}

// Lookup returns all IOC entries recorded for a module path.
func (s *Set) Lookup(path string) []Entry {
	return s.entries[path]
}

// Allowed reports whether a module path is on the allowlist.
func (s *Set) Allowed(path string) bool {
	_, ok := s.allow[path]
	return ok
}

// Len returns the number of IOC entries in the set.
func (s *Set) Len() int {
	n := 0
	for _, es := range s.entries {
		n += len(es)
	}
	return n
}

// Merge copies every entry and allowlisted path from other into s.
func (s *Set) Merge(other *Set) {
	if other == nil {
		return
	}
	for _, es := range other.entries {
		for _, e := range es {
			s.Add(e)
		}
	}
	for p := range other.allow {
		s.AddAllow(p)
	}
}

// Parse sniffs data as JSON or CSV and loads it into a Set. The source
// label records where the data came from (a URL or file path) so reports
// can cite it.
func Parse(data []byte, source string) (*Set, error) {
	trimmed := bytes.TrimLeftFunc(data, unicode.IsSpace)
	if len(trimmed) == 0 {
		return nil, errors.New("IOC data is empty")
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return ParseJSON(data, source)
	}
	return ParseCSV(data, source)
}
