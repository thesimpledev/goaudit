package feed

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// makeZip builds an in-memory archive from name→content pairs.
func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractZipMembersFilters(t *testing.T) {
	data := makeZip(t, map[string]string{
		"MAL-2026-0001.json":        `{"id":"MAL-2026-0001"}`,
		"nested/MAL-2026-0002.json": `{"id":"MAL-2026-0002"}`,
		"GO-2026-1234.json":         `{"id":"GO-2026-1234"}`,
		"MAL-2026-0003.txt":         "wrong suffix",
		"README.md":                 "docs",
	})
	members, err := ExtractZipMembers(data, "MAL-", ".json")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 2 {
		t.Fatalf("got %d members, want 2", len(members))
	}
	joined := string(bytes.Join(members, []byte("\n")))
	for _, want := range []string{"MAL-2026-0001", "MAL-2026-0002"} {
		if !strings.Contains(joined, want) {
			t.Errorf("members missing %s:\n%s", want, joined)
		}
	}
	for _, reject := range []string{"GO-2026-1234", "wrong suffix", "docs"} {
		if strings.Contains(joined, reject) {
			t.Errorf("members should not contain %q", reject)
		}
	}
}

func TestExtractZipMembersNoMatches(t *testing.T) {
	data := makeZip(t, map[string]string{"GO-2026-1.json": "{}"})
	members, err := ExtractZipMembers(data, "MAL-", ".json")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 0 {
		t.Fatalf("got %d members, want 0", len(members))
	}
}

func TestExtractZipMembersCorruptArchive(t *testing.T) {
	if _, err := ExtractZipMembers([]byte("this is not a zip file"), "MAL-", ".json"); err == nil {
		t.Fatal("corrupt archive should error")
	}
}

func TestExtractZipMembersOversizedMember(t *testing.T) {
	data := makeZip(t, map[string]string{
		"MAL-huge.json": strings.Repeat("x", maxZipMemberBytes+1),
	})
	if _, err := ExtractZipMembers(data, "MAL-", ".json"); err == nil {
		t.Fatal("oversized member should error")
	}
}
