package ioc

import (
	"strings"
	"testing"
)

// malRecord mirrors the shape of a real OpenSSF malicious-packages report
// served by OSV.dev (MAL-2026-3628, trimmed).
const malRecord = `{
  "schema_version": "1.7.5",
  "id": "MAL-2026-3628",
  "summary": "Malicious code in github.com/BufferZoneCorp/log-core (Go)",
  "details": "\n---\n_-= Per source details. Do not edit below this line.=-_\n\n## Source: google-open-source-security\nThis package steals credentials and tampers with build environments.\n",
  "affected": [
    {
      "package": {
        "name": "github.com/BufferZoneCorp/log-core",
        "ecosystem": "Go",
        "purl": "pkg:golang/github.com/BufferZoneCorp/log-core"
      },
      "ranges": [
        {"type": "SEMVER", "events": [{"introduced": "0"}]}
      ]
    }
  ]
}`

func TestParseOSVSingleRecordAllVersions(t *testing.T) {
	set, err := ParseOSV([]byte(malRecord), "test-feed")
	if err != nil {
		t.Fatal(err)
	}
	entries := set.Lookup("github.com/BufferZoneCorp/log-core")
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	e := entries[0]
	if len(e.Versions) != 0 {
		t.Errorf("unbounded range must flag all versions, got %v", e.Versions)
	}
	if !e.MatchVersion("v9.9.9") {
		t.Error("entry should match every version")
	}
	if e.Campaign != "MAL-2026-3628" {
		t.Errorf("campaign = %q, want the record ID", e.Campaign)
	}
	if !strings.Contains(e.Reason, "Malicious code") {
		t.Errorf("reason should carry the summary, got %q", e.Reason)
	}
	if e.Source != "https://osv.dev/vulnerability/MAL-2026-3628" {
		t.Errorf("source = %q", e.Source)
	}
}

func TestParseOSVArray(t *testing.T) {
	data := `[` + malRecord + `,{
	  "id": "MAL-2026-9999",
	  "summary": "Malicious code in github.com/evil/other (Go)",
	  "affected": [{"package": {"name": "github.com/evil/other", "ecosystem": "Go"}}]
	}]`
	set, err := ParseOSV([]byte(data), "test-feed")
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2", set.Len())
	}
	if len(set.Lookup("github.com/evil/other")) != 1 {
		t.Error("second record not loaded")
	}
}

func TestParseOSVExplicitVersionsWithBoundedRange(t *testing.T) {
	data := `{
	  "id": "MAL-2026-0042",
	  "summary": "Malicious versions of example.com/mod",
	  "affected": [{
	    "package": {"name": "example.com/mod", "ecosystem": "Go"},
	    "versions": ["1.2.3", "1.2.4"],
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.2.3"}, {"fixed": "1.2.5"}]}]
	  }]
	}`
	set, err := ParseOSV([]byte(data), "test-feed")
	if err != nil {
		t.Fatal(err)
	}
	e := set.Lookup("example.com/mod")[0]
	if len(e.Versions) != 2 {
		t.Fatalf("bounded range should keep the explicit versions, got %v", e.Versions)
	}
	if !e.MatchVersion("v1.2.3") || e.MatchVersion("v1.2.5") {
		t.Error("version matching wrong for explicit list")
	}
}

func TestParseOSVExplicitVersionsWithUnboundedRange(t *testing.T) {
	data := `{
	  "id": "MAL-2026-0043",
	  "summary": "s",
	  "affected": [{
	    "package": {"name": "example.com/mod2", "ecosystem": "Go"},
	    "versions": ["1.0.0"],
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
	  }]
	}`
	set, err := ParseOSV([]byte(data), "test-feed")
	if err != nil {
		t.Fatal(err)
	}
	e := set.Lookup("example.com/mod2")[0]
	if len(e.Versions) != 0 {
		t.Errorf("an unbounded range must override the version list, got %v", e.Versions)
	}
}

func TestParseOSVSkipsOtherEcosystems(t *testing.T) {
	data := `{
	  "id": "MAL-2026-0044",
	  "summary": "npm package",
	  "affected": [
	    {"package": {"name": "evil-npm-pkg", "ecosystem": "npm"}},
	    {"package": {"name": "github.com/evil/gopkg", "ecosystem": "Go"}},
	    {"package": {"name": "no-ecosystem-pkg", "ecosystem": ""}}
	  ]
	}`
	set, err := ParseOSV([]byte(data), "test-feed")
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (only the Go package)", set.Len())
	}
	if len(set.Lookup("github.com/evil/gopkg")) != 1 {
		t.Error("Go package missing")
	}
}

func TestParseOSVDetailsFallback(t *testing.T) {
	data := `{
	  "id": "MAL-2026-0045",
	  "details": "\n---\n_-= boilerplate =-_\n\n## Source: x\nActual description line.\n",
	  "affected": [{"package": {"name": "example.com/mod3", "ecosystem": "Go"}}]
	}`
	set, err := ParseOSV([]byte(data), "test-feed")
	if err != nil {
		t.Fatal(err)
	}
	e := set.Lookup("example.com/mod3")[0]
	if e.Reason != "Actual description line." {
		t.Errorf("reason = %q", e.Reason)
	}
}

func TestParseOSVMalformed(t *testing.T) {
	if _, err := ParseOSV([]byte("{not json"), "test-feed"); err == nil {
		t.Fatal("malformed JSON should error")
	}
	if _, err := ParseOSV([]byte("   "), "test-feed"); err == nil {
		t.Fatal("empty data should error")
	}
}
