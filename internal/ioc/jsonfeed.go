package ioc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// jsonEntry accepts the field names used by common feed formats. The first
// non-empty of Module, Package, and Name is taken as the module path.
type jsonEntry struct {
	Module    string   `json:"module"`
	Package   string   `json:"package"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Versions  []string `json:"versions"`
	Ecosystem string   `json:"ecosystem"`
	Campaign  string   `json:"campaign"`
	Reason    string   `json:"reason"`
	Notes     string   `json:"notes"`
}

type jsonFeed struct {
	Entries []jsonEntry `json:"entries"`
	Allow   []string    `json:"allow"`
}

// ParseJSON loads a JSON IOC feed. It accepts either an object with
// "entries" (and an optional "allow" list), or a bare array of entries.
// Entries tagged with a non-Go ecosystem are skipped.
func ParseJSON(data []byte, source string) (*Set, error) {
	trimmed := bytes.TrimLeftFunc(data, unicode.IsSpace)
	var feed jsonFeed
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(data, &feed.Entries); err != nil {
			return nil, fmt.Errorf("parse JSON IOC feed %s: %w", source, err)
		}
	} else if err := json.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("parse JSON IOC feed %s: %w", source, err)
	}

	set := NewSet()
	for _, je := range feed.Entries {
		if !goEcosystem(je.Ecosystem) {
			continue
		}
		versions := je.Versions
		if je.Version != "" {
			versions = append(versions, je.Version)
		}
		set.Add(Entry{
			Module:   firstNonEmpty(je.Module, je.Package, je.Name),
			Versions: versions,
			Campaign: je.Campaign,
			Reason:   firstNonEmpty(je.Reason, je.Notes),
			Source:   source,
		})
	}
	for _, p := range feed.Allow {
		set.AddAllow(p)
	}
	return set, nil
}

// goEcosystem reports whether an ecosystem label refers to Go. An empty
// label counts as Go so feeds without ecosystem tagging still load.
func goEcosystem(label string) bool {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "", "go", "golang", "gomod":
		return true
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
