package licenseexpr

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// malformedExpressions are values the underlying SPDX parser panics on rather
// than rejecting. They reach Bomly from lockfiles and registry APIs, so every
// entry point has to survive them.
var malformedExpressions = []string{
	"(((",
	"((((((((((",
	"(( (",
	"(MIT AND (((",
}

func TestValidRejectsMalformedExpressionsWithoutPanicking(t *testing.T) {
	for _, expression := range malformedExpressions {
		if Valid(expression) {
			t.Fatalf("expected %q to be reported invalid", expression)
		}
	}
}

func TestValid(t *testing.T) {
	valid := []string{"MIT", "MIT OR Apache-2.0", "Apache-2.0 AND (MIT OR BSD-3-Clause)", "GPL-2.0-only+"}
	for _, expression := range valid {
		if !Valid(expression) {
			t.Fatalf("expected %q to be valid", expression)
		}
	}
	invalid := []string{"", "   ", "non-standard", "see LICENSE file", "MIT AND"}
	for _, expression := range invalid {
		if Valid(expression) {
			t.Fatalf("expected %q to be invalid", expression)
		}
	}
}

func TestValidateAllReportsEveryValueWhenTheParserGivesUp(t *testing.T) {
	values := []string{"MIT", "((("}
	valid, invalid := ValidateAll(values)
	if valid {
		t.Fatal("expected the batch to be invalid")
	}
	if len(invalid) != len(values) {
		t.Fatalf("expected every value reported unchecked, got %#v", invalid)
	}
}

func TestValidateAll(t *testing.T) {
	if valid, invalid := ValidateAll(nil); !valid || invalid != nil {
		t.Fatalf("expected an empty batch to be valid, got %v %#v", valid, invalid)
	}
	if valid, _ := ValidateAll([]string{"MIT", "Apache-2.0"}); !valid {
		t.Fatal("expected known identifiers to validate")
	}
	valid, invalid := ValidateAll([]string{"MIT", "non-standard"})
	if valid {
		t.Fatal("expected free text to be reported invalid")
	}
	if len(invalid) != 1 || invalid[0] != "non-standard" {
		t.Fatalf("expected only the free-text value reported, got %#v", invalid)
	}
}

func TestIdentifier(t *testing.T) {
	tests := []struct {
		value string
		want  string
		ok    bool
	}{
		{value: "MIT", want: "MIT", ok: true},
		{value: "mit", want: "MIT", ok: true},
		{value: "  Apache-2.0  ", want: "Apache-2.0", ok: true},
		{value: "GPL-2.0", want: "GPL-2.0", ok: true}, // deprecated, still a list entry
		{value: "MIT OR Apache-2.0"},
		{value: "GPL-2.0-only+"},
		{value: "(MIT)"},
		{value: "non-standard"},
		{value: ""},
	}
	for _, tc := range tests {
		got, ok := Identifier(tc.value)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("Identifier(%q) = (%q, %v), want (%q, %v)", tc.value, got, ok, tc.want, tc.ok)
		}
	}
}

func TestSatisfiesAndExtractSurviveMalformedExpressions(t *testing.T) {
	for _, expression := range malformedExpressions {
		if ok, err := Satisfies(expression, []string{"MIT"}); ok {
			t.Fatalf("expected %q to satisfy nothing (err %v)", expression, err)
		}
		if licenses, err := Extract(expression); len(licenses) != 0 {
			t.Fatalf("expected %q to yield no licenses, got %#v (err %v)", expression, licenses, err)
		}
	}
}

func TestSatisfiesAndExtract(t *testing.T) {
	ok, err := Satisfies("MIT", []string{"MIT", "Apache-2.0"})
	if err != nil || !ok {
		t.Fatalf("expected MIT to be satisfied, got %v (err %v)", ok, err)
	}
	ok, err = Satisfies("GPL-3.0-only", []string{"MIT"})
	if err != nil || ok {
		t.Fatalf("expected GPL not to be satisfied by MIT, got %v (err %v)", ok, err)
	}
	licenses, err := Extract("MIT OR Apache-2.0")
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(licenses) != 2 {
		t.Fatalf("expected 2 extracted licenses, got %#v", licenses)
	}
}

// TestNoDirectSPDXExpressionUse keeps the panic guard from being bypassed. The
// underlying parser crashes on malformed input, so a call site that reaches it
// directly reintroduces a crash on data a repository controls. New callers
// belong in this package.
func TestNoDirectSPDXExpressionUse(t *testing.T) {
	const spdxModule = "github.com/github/go-spdx"

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	selfDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve package directory: %v", err)
	}

	fset := token.NewFileSet()
	walkErr := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if dir := filepath.Dir(path); dir == selfDir {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return nil // not this test's job to police unparseable files
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			if strings.HasPrefix(importPath, spdxModule) {
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					rel = path
				}
				t.Errorf("%s imports %s directly; use internal/licenseexpr, which guards the parser's panics", rel, importPath)
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk internal packages: %v", walkErr)
	}
}
