package ioc

import "testing"

func TestParseJSONObject(t *testing.T) {
	data := []byte(`{
		"version": 1,
		"entries": [
			{"module": "github.com/evil/pkg", "versions": ["v1.0.0", "v1.0.1"], "campaign": "PolinRider", "reason": "stealer"},
			{"package": "github.com/other/pkg", "version": "v2.0.0", "notes": "dropper"}
		],
		"allow": ["github.com/trusted/pkg"]
	}`)
	set, err := Parse(data, "test.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2", set.Len())
	}
	entries := set.Lookup("github.com/evil/pkg")
	if len(entries) != 1 || entries[0].Campaign != "PolinRider" {
		t.Fatalf("Lookup evil/pkg = %+v", entries)
	}
	other := set.Lookup("github.com/other/pkg")
	if len(other) != 1 || other[0].Reason != "dropper" || len(other[0].Versions) != 1 {
		t.Fatalf("package/notes aliases not honored: %+v", other)
	}
	if !set.Allowed("github.com/trusted/pkg") {
		t.Error("allowlist entry not loaded")
	}
}

func TestParseJSONArray(t *testing.T) {
	data := []byte(`[{"name": "github.com/evil/pkg", "campaign": "X"}]`)
	set, err := Parse(data, "test.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("Len = %d, want 1", set.Len())
	}
}

func TestParseJSONEcosystemFilter(t *testing.T) {
	data := []byte(`{"entries": [
		{"module": "evil-npm-pkg", "ecosystem": "npm"},
		{"module": "github.com/evil/gopkg", "ecosystem": "Go"},
		{"module": "github.com/evil/untagged"}
	]}`)
	set, err := Parse(data, "test.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (npm entry should be filtered)", set.Len())
	}
	if len(set.Lookup("evil-npm-pkg")) != 0 {
		t.Error("npm entry was not filtered out")
	}
}

func TestParseCSV(t *testing.T) {
	data := []byte("Package,Version,Ecosystem,Campaign,Notes\n" +
		"github.com/evil/pkg,v1.0.0|v1.1.0,go,PolinRider,stealer\n" +
		"evil-npm-thing,1.0.0,npm,PolinRider,skip me\n" +
		"github.com/evil/other,,golang,PolinRider,all versions\n")
	set, err := Parse(data, "test.csv")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2", set.Len())
	}
	entries := set.Lookup("github.com/evil/pkg")
	if len(entries) != 1 || len(entries[0].Versions) != 2 {
		t.Fatalf("versions not split: %+v", entries)
	}
	all := set.Lookup("github.com/evil/other")
	if len(all) != 1 || len(all[0].Versions) != 0 {
		t.Fatalf("empty version cell should mean all versions: %+v", all)
	}
}

func TestParseCSVSocketFormat(t *testing.T) {
	data := []byte("Ecosystem,Namespace,Name,Version,Artifact,Published,Detected\n" +
		"npm,,tailwind-animationbased,2.3.6,,2025-12-07,2025-12-07\n" +
		"golang,github.com/zainirfan13,graphql-client,v0.0.0-20220912215956-d304e79da123,,2022-09-12,2026-06-30\n" +
		"composer,vendor,evil-php,1.0.0,,2025-01-01,2025-01-02\n")
	set, err := Parse(data, "packages.csv")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (only the golang row)", set.Len())
	}
	entries := set.Lookup("github.com/zainirfan13/graphql-client")
	if len(entries) != 1 {
		t.Fatalf("namespace+name not joined into a module path: %+v", entries)
	}
	if !entries[0].MatchVersion("v0.0.0-20220912215956-d304e79da123") {
		t.Error("pinned pseudo-version should match")
	}
	if entries[0].MatchVersion("v1.0.0") {
		t.Error("other versions should not match")
	}
}

func TestParseCSVMissingModuleColumn(t *testing.T) {
	data := []byte("Foo,Bar\n1,2\n")
	if _, err := Parse(data, "test.csv"); err == nil {
		t.Fatal("expected an error for a CSV without a module column")
	}
}

func TestParseEmpty(t *testing.T) {
	if _, err := Parse([]byte("  \n"), "empty"); err == nil {
		t.Fatal("expected an error for empty data")
	}
}

func TestMatchVersion(t *testing.T) {
	anyVersion := Entry{Module: "m"}
	if !anyVersion.MatchVersion("v9.9.9") {
		t.Error("entry without versions should match any version")
	}
	pinned := Entry{Module: "m", Versions: []string{"1.2.3", "v2.0.0+incompatible"}}
	if !pinned.MatchVersion("v1.2.3") {
		t.Error("v-prefix should normalize")
	}
	if !pinned.MatchVersion("v2.0.0") {
		t.Error("+incompatible should normalize")
	}
	if pinned.MatchVersion("v1.2.4") {
		t.Error("unlisted version should not match")
	}
}

func TestMerge(t *testing.T) {
	a := NewSet()
	a.Add(Entry{Module: "github.com/a/a"})
	b := NewSet()
	b.Add(Entry{Module: "github.com/b/b"})
	b.AddAllow("github.com/ok/ok")
	a.Merge(b)
	a.Merge(nil)
	if a.Len() != 2 || !a.Allowed("github.com/ok/ok") {
		t.Fatalf("merge failed: len=%d", a.Len())
	}
}
