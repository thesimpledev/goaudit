package match

import (
	"testing"

	"github.com/thesimpledev/goaudit/internal/ioc"
	"github.com/thesimpledev/goaudit/internal/modgraph"
)

func newTestEngine() *Engine {
	set := ioc.NewSet()
	set.Add(ioc.Entry{Module: "github.com/evil/stealer", Campaign: "PolinRider", Reason: "credential stealer"})
	set.Add(ioc.Entry{Module: "github.com/shady/lib", Versions: []string{"v1.2.3"}})
	set.AddAllow("github.com/trusted/fork")
	return NewEngine(set)
}

func TestCheckModuleExactIOC(t *testing.T) {
	e := newTestEngine()
	f := e.CheckModule(modgraph.Module{Path: "github.com/evil/stealer", Version: "v0.9.0"})
	if f.Status != Flagged {
		t.Fatalf("status = %v, want flagged (finding: %+v)", f.Status, f)
	}
	if f.Rule != "ioc" {
		t.Errorf("rule = %q, want ioc", f.Rule)
	}
}

func TestCheckModuleVersionPinned(t *testing.T) {
	e := newTestEngine()
	f := e.CheckModule(modgraph.Module{Path: "github.com/shady/lib", Version: "v1.2.3"})
	if f.Status != Flagged {
		t.Fatalf("listed version: status = %v, want flagged", f.Status)
	}
	f = e.CheckModule(modgraph.Module{Path: "github.com/shady/lib", Version: "v2.0.0"})
	if f.Status != Warning || f.Rule != "ioc-module" {
		t.Fatalf("other version: got status %v rule %q, want warning/ioc-module", f.Status, f.Rule)
	}
}

func TestTyposquatDistance(t *testing.T) {
	e := newTestEngine()
	f := e.CheckModule(modgraph.Module{Path: "github.com/strechr/testify", Version: "v1.9.0"})
	if f.Status != Warning || f.Rule != "typosquat" {
		t.Fatalf("got status %v rule %q, want warning/typosquat (detail: %s)", f.Status, f.Rule, f.Detail)
	}
}

func TestPopularModulesAreClean(t *testing.T) {
	e := newTestEngine()
	popular := []string{
		"github.com/stretchr/testify",
		"gopkg.in/yaml.v3",
		"github.com/golang-jwt/jwt/v5",
		"golang.org/x/sync",
		"github.com/go-chi/chi/v5",
	}
	for _, path := range popular {
		f := e.CheckModule(modgraph.Module{Path: path, Version: "v1.0.0"})
		if f.Status != Clean {
			t.Errorf("%s: status = %v (%s), want clean", path, f.Status, f.Detail)
		}
	}
}

func TestOwnerMismatchImitation(t *testing.T) {
	e := newTestEngine()
	// Owner names dressed up from a popular owner must warn. The exact
	// rule may be "typosquat" when the whole path is also within edit
	// distance (e.g. a case swap), so only the status is asserted here.
	imitators := []string{
		"github.com/stretchr-dev/testify", // popular owner + suffix
		"github.com/Gorilla/websocket",    // case-swapped owner
		"github.com/hashicorp-io/go-version",
	}
	for _, path := range imitators {
		f := e.CheckModule(modgraph.Module{Path: path, Version: "v1.0.0"})
		if f.Status != Warning {
			t.Errorf("%s: got status %v (%s), want warning", path, f.Status, f.Detail)
		}
	}
	f := e.CheckModule(modgraph.Module{Path: "github.com/stretchr-dev/testify", Version: "v1.0.0"})
	if f.Rule != "owner-mismatch" {
		t.Errorf("rule = %q, want owner-mismatch", f.Rule)
	}
}

func TestUnrelatedOwnersSharingNamesAreClean(t *testing.T) {
	e := newTestEngine()
	// Real-world false positives: honest projects that merely share a
	// repo name with a more popular module.
	legit := []string{
		"github.com/coder/websocket",
		"github.com/tidwall/pretty",
		"github.com/cncf/udpa/go",
		"github.com/cncf/xds/go",
		"github.com/mcuadros/go-version",
		"github.com/getlantern/errors",
		"github.com/evilcorp/testify", // unrelated owner: not an imitation
	}
	for _, path := range legit {
		f := e.CheckModule(modgraph.Module{Path: path, Version: "v1.0.0"})
		if f.Status != Clean {
			t.Errorf("%s: status = %v (%s), want clean", path, f.Status, f.Detail)
		}
	}
}

func TestAllowlist(t *testing.T) {
	e := newTestEngine()
	f := e.CheckModule(modgraph.Module{Path: "github.com/trusted/fork", Version: "v1.0.0"})
	if f.Status != Clean || f.Rule != "allowlist" {
		t.Fatalf("got status %v rule %q, want clean/allowlist", f.Status, f.Rule)
	}
}

func TestReplaceTargetChecked(t *testing.T) {
	e := newTestEngine()
	f := e.CheckModule(modgraph.Module{
		Path:    "github.com/fine/lib",
		Version: "v1.0.0",
		Replace: &modgraph.Module{Path: "github.com/evil/stealer", Version: "v1.0.0"},
	})
	if f.Status != Flagged {
		t.Fatalf("module replace: status = %v, want flagged (detail: %s)", f.Status, f.Detail)
	}
	if f.Module != "github.com/fine/lib" {
		t.Errorf("finding reported under %q, want the required path", f.Module)
	}

	f = e.CheckModule(modgraph.Module{
		Path:    "github.com/fine/lib",
		Version: "v1.0.0",
		Replace: &modgraph.Module{Path: "../local"},
	})
	if f.Status != Clean {
		t.Fatalf("filesystem replace: status = %v, want clean", f.Status)
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"github.com/go-chi/chi/v5", "github.com/go-chi/chi"},
		{"gopkg.in/yaml.v3", "gopkg.in/yaml"},
		{"github.com/aws/aws-sdk-go-v2", "github.com/aws/aws-sdk-go-v2"},
		{"github.com/plain/module", "github.com/plain/module"},
	}
	for _, tt := range tests {
		if got := normalizePath(tt.in); got != tt.want {
			t.Errorf("normalizePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
