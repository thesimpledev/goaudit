package ioc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// osvRecord holds the fields of an OSV-schema record that map onto IOC
// entries. The OpenSSF malicious-packages database publishes its reports in
// this format, served by OSV.dev under MAL- identifiers.
type osvRecord struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Affected []osvAffected `json:"affected"`
}

type osvAffected struct {
	Package  osvPackage `json:"package"`
	Versions []string   `json:"versions"`
	Ranges   []osvRange `json:"ranges"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvRange struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

// ParseOSV loads OSV-schema JSON — a single record or an array of records —
// into a Set. Only packages in the Go ecosystem are kept. The source label
// records where the data came from so reports can cite it.
func ParseOSV(data []byte, source string) (*Set, error) {
	trimmed := bytes.TrimLeftFunc(data, unicode.IsSpace)
	if len(trimmed) == 0 {
		return nil, errors.New("OSV data is empty")
	}
	var records []osvRecord
	if trimmed[0] == '[' {
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, fmt.Errorf("parse OSV feed %s: %w", source, err)
		}
	} else {
		var rec osvRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, fmt.Errorf("parse OSV feed %s: %w", source, err)
		}
		records = append(records, rec)
	}

	set := NewSet()
	for _, rec := range records {
		addOSVRecord(set, rec)
	}
	return set, nil
}

func addOSVRecord(set *Set, rec osvRecord) {
	reason := strings.TrimSpace(rec.Summary)
	if reason == "" {
		reason = firstDetailLine(rec.Details)
	}
	for _, aff := range rec.Affected {
		if strings.TrimSpace(aff.Package.Ecosystem) == "" || !goEcosystem(aff.Package.Ecosystem) {
			continue
		}
		set.Add(Entry{
			Module:   aff.Package.Name,
			Versions: affectedVersions(aff),
			Campaign: rec.ID,
			Reason:   reason,
			Source:   "https://osv.dev/vulnerability/" + rec.ID,
		})
	}
}

// affectedVersions returns the explicit version list only when it is
// exhaustive: every range must be bounded by a "fixed" event. Any unbounded
// range (introduced 0, no fix) means every version is affected, expressed
// as an empty list. When in doubt the entry flags all versions — the safe
// failure mode for malware.
func affectedVersions(aff osvAffected) []string {
	if len(aff.Versions) == 0 {
		return nil
	}
	for _, r := range aff.Ranges {
		if !rangeBounded(r) {
			return nil
		}
	}
	return aff.Versions
}

// rangeBounded reports whether a range contains a "fixed" event, i.e. does
// not extend to every future version.
func rangeBounded(r osvRange) bool {
	for _, ev := range r.Events {
		if _, ok := ev["fixed"]; ok {
			return true
		}
	}
	return false
}

// firstDetailLine extracts the first content line of an OSV details block,
// skipping the "---" separator boilerplate the malicious-packages reports
// start with.
func firstDetailLine(details string) string {
	for _, line := range strings.Split(details, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "-") || strings.HasPrefix(t, "_") || strings.HasPrefix(t, "#") {
			continue
		}
		return t
	}
	return ""
}
