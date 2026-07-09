package ioc

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ParseCSV loads a CSV IOC feed. The first row must be a header; column
// names are matched loosely (module/package/name, version/versions,
// ecosystem/registry/type, campaign, reason/notes/description). Rows
// tagged with a non-Go ecosystem are skipped.
func ParseCSV(data []byte, source string) (*Set, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true

	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("parse CSV IOC feed %s: %w", source, err)
	}
	cols := mapColumns(header)
	_, hasModule := cols["module"]
	_, hasName := cols["name"]
	if !hasModule && !hasName {
		return nil, errors.New("CSV IOC feed has no module/package/name column")
	}

	set := NewSet()
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse CSV IOC feed %s: %w", source, err)
		}
		if !goEcosystem(field(rec, cols, "ecosystem")) {
			continue
		}
		set.Add(Entry{
			Module:   modulePath(rec, cols),
			Versions: splitVersions(field(rec, cols, "version")),
			Campaign: field(rec, cols, "campaign"),
			Reason:   field(rec, cols, "reason"),
			Source:   source,
		})
	}
	return set, nil
}

// modulePath builds the module path from a row. Feeds like Socket's split
// it across Namespace ("github.com/owner") and Name ("repo") columns;
// others carry the full path in one column.
func modulePath(rec []string, cols map[string]int) string {
	if module := field(rec, cols, "module"); module != "" {
		return module
	}
	name := field(rec, cols, "name")
	if ns := field(rec, cols, "namespace"); ns != "" && name != "" {
		return strings.TrimSuffix(ns, "/") + "/" + name
	}
	return name
}

// mapColumns assigns a role to each recognized header column. The first
// matching column wins when a role appears more than once.
func mapColumns(header []string) map[string]int {
	cols := make(map[string]int)
	assign := func(role string, i int) {
		if _, taken := cols[role]; !taken {
			cols[role] = i
		}
	}
	for i, h := range header {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "module", "package", "package_name", "module_path":
			assign("module", i)
		case "name":
			assign("name", i)
		case "namespace":
			assign("namespace", i)
		case "version", "versions", "package_version":
			assign("version", i)
		case "ecosystem", "registry", "type":
			assign("ecosystem", i)
		case "campaign", "attack", "attack_name":
			assign("campaign", i)
		case "reason", "notes", "description", "details":
			assign("reason", i)
		}
	}
	return cols
}

func field(rec []string, cols map[string]int, role string) string {
	i, ok := cols[role]
	if !ok || i >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[i])
}

// splitVersions splits a version cell on "|" or ";" so feeds can list
// several bad versions in one field.
func splitVersions(cell string) []string {
	if cell == "" {
		return nil
	}
	parts := strings.FieldsFunc(cell, func(r rune) bool {
		return r == '|' || r == ';'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
