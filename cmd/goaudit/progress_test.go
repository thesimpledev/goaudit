package main

import (
	"bytes"
	"testing"
)

func TestProgressLine(t *testing.T) {
	got := progressLine(12, 93, "thesimpledev/aiCallBot")
	want := "auditing [12/93] thesimpledev/aiCallBot"
	if got != want {
		t.Errorf("progressLine = %q, want %q", got, want)
	}
}

func TestProgressSilentOnNonTerminal(t *testing.T) {
	var buf bytes.Buffer
	p := newProgress(&buf)
	if p.enabled {
		t.Fatal("progress must be disabled for non-terminal writers")
	}
	p.setTotal(3)
	p.announce("starting…")
	p.step("owner/repo")
	p.finish()
	if buf.Len() != 0 {
		t.Errorf("disabled progress wrote output: %q", buf.String())
	}
}

func TestProgressPadsShorterLines(t *testing.T) {
	var buf bytes.Buffer
	p := &progress{w: &buf, enabled: true, total: 2}
	p.step("a-very-long-project-name")
	p.step("x")
	out := buf.String()
	if len(out) == 0 {
		t.Fatal("enabled progress wrote nothing")
	}
	// The second, shorter line must be padded to fully overwrite the first.
	lines := bytes.Split([]byte(out), []byte("\r"))
	last := lines[len(lines)-1]
	if len(last) < len("auditing [1/2] a-very-long-project-name") {
		t.Errorf("short line not padded over the longer one: %q", last)
	}
}
