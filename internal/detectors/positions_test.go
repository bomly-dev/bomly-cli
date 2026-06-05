package detectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestAttachPositionsNilSafe(t *testing.T) {
	// All-nil inputs must not panic.
	AttachPositions(nil, nil, nil)
	AttachPositions(sdk.New(), nil, func(*sdk.Dependency) string { return "" })
	AttachPositions(sdk.New(), map[string]*sdk.SourcePosition{"x": {File: "f"}}, nil)
}

func TestAttachPositionsDoesNotDuplicate(t *testing.T) {
	g := sdk.New()
	pkg := sdk.NewDependency(sdk.Dependency{
		Name:      "foo",
		Version:   "1.0.0",
		Ecosystem: "test",
		Locations: []sdk.PackageLocation{
			{RealPath: "lock.txt", Position: &sdk.SourcePosition{File: "lock.txt", Line: 1}},
		},
	})
	_ = g.AddNode(pkg)

	positions := map[string]*sdk.SourcePosition{
		"foo": {File: "lock.txt", Line: 5},
	}
	AttachPositions(g, positions, func(p *sdk.Dependency) string { return p.Name })

	got, _ := g.Node("foo@1.0.0")
	if got == nil {
		t.Fatal("missing foo")
	}
	if len(got.Locations) != 1 {
		t.Errorf("duplicate Location added; got %d, want 1", len(got.Locations))
	}
}

func TestAttachPositionsHonorsNameKey(t *testing.T) {
	g := sdk.New()
	pkg := sdk.NewDependency(sdk.Dependency{Name: "Foo", Version: "1", Ecosystem: "test"})
	_ = g.AddNode(pkg)

	// Map keyed by lowercase name; nameKey lowercases the node.
	positions := map[string]*sdk.SourcePosition{"foo": {File: "lock", Line: 42}}
	AttachPositions(g, positions, func(p *sdk.Dependency) string {
		return toLower(p.Name)
	})

	got, _ := g.Node("Foo@1")
	if got == nil {
		t.Fatal("missing Foo")
	}
	if len(got.Locations) != 1 {
		t.Fatalf("Locations = %d, want 1", len(got.Locations))
	}
	if got.Locations[0].Position == nil || got.Locations[0].Position.Line != 42 {
		t.Errorf("Position = %+v, want line 42", got.Locations[0].Position)
	}
}

func TestScanLinesReportsLineNumbers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(path, []byte("a\nb\nc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var lines []int
	var texts []string
	if err := ScanLines(path, func(line int, text string) {
		lines = append(lines, line)
		texts = append(texts, text)
	}); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 || lines[0] != 1 || lines[2] != 3 {
		t.Errorf("lines = %v, want [1 2 3]", lines)
	}
	if texts[1] != "b" {
		t.Errorf("texts[1] = %q, want b", texts[1])
	}
}

func TestScanLinesMissingFileSilent(t *testing.T) {
	if err := ScanLines(filepath.Join(t.TempDir(), "missing"), func(int, string) {}); err != nil {
		t.Errorf("ScanLines on missing file should be silent; got %v", err)
	}
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
