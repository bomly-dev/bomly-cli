package govulncheck

import (
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

const sampleGovulncheckJSON = `
{"config":{"protocol_version":"v1.0.0"}}
{"progress":{"message":"loaded packages"}}
{"osv":{"id":"GO-2024-1234","aliases":["CVE-2024-1234","GHSA-aaaa-bbbb-cccc"],"summary":"oops"}}
{"finding":{"osv":"GO-2024-1234","fixed_version":"v1.2.3","trace":[{"module":"example.com/app","package":"main","function":"main","position":{"filename":"main.go","line":12,"column":4}},{"module":"github.com/foo/bar","version":"v1.0.0","package":"github.com/foo/bar","function":"Decode","position":{"filename":"decode.go","line":99}}]}}
{"finding":{"osv":"GO-2024-1234","trace":[{"module":"example.com/app","package":"main","function":"handler","position":{"filename":"handler.go","line":7}},{"module":"github.com/foo/bar","version":"v1.0.0","package":"github.com/foo/bar","function":"Decode","position":{"filename":"decode.go","line":99}}]}}
{"finding":{"osv":"GO-2024-9999"}}
`

func TestParseGovulncheckJSONStreamCollapsesTracesPerOSV(t *testing.T) {
	r, err := parseGovulncheckJSON([]byte(sampleGovulncheckJSON))
	if err != nil {
		t.Fatal(err)
	}
	first, ok := r.Findings["GO-2024-1234"]
	if !ok {
		t.Fatalf("missing GO-2024-1234: %+v", r.Findings)
	}
	if !first.CalledBy {
		t.Error("CalledBy should be true when finding has a trace")
	}
	if !first.ImportedBy {
		t.Error("ImportedBy should be true once any finding records the module")
	}
	if first.FixedIn != "v1.2.3" {
		t.Errorf("FixedIn = %q, want v1.2.3", first.FixedIn)
	}
	if got, want := len(first.CallPaths), 2; got != want {
		t.Errorf("CallPaths count = %d, want %d", got, want)
	}
	if got, want := len(first.Symbols), 1; got != want {
		t.Errorf("Symbols dedup'd to %d, want %d (%+v)", got, want, first.Symbols)
	}
	if first.Symbols[0].Symbol != "Decode" || first.Symbols[0].Package != "github.com/foo/bar" {
		t.Errorf("unexpected sink symbol: %+v", first.Symbols[0])
	}
	wantPos := model.SourcePosition{File: "main.go", Line: 12, Column: 4}
	if first.CallPaths[0].Frames[0].Position != wantPos {
		t.Errorf("frame position = %+v, want %+v", first.CallPaths[0].Frames[0].Position, wantPos)
	}
	if got := first.Aliases; len(got) != 2 || got[0] != "CVE-2024-1234" {
		t.Errorf("aliases = %+v, want [CVE-2024-1234, GHSA-...]", got)
	}

	second, ok := r.Findings["GO-2024-9999"]
	if !ok {
		t.Fatal("missing GO-2024-9999")
	}
	if second.CalledBy {
		t.Error("CalledBy should be false for traceless finding")
	}
	if !second.ImportedBy {
		t.Error("ImportedBy should be true for traceless finding (govulncheck reported it)")
	}

	if _, ok := r.ImportedModules["github.com/foo/bar"]; !ok {
		t.Errorf("ImportedModules should include github.com/foo/bar, got %+v", r.ImportedModules)
	}
}

func TestParseGovulncheckJSONTolertaesUnknownEnvelopeKeys(t *testing.T) {
	in := []byte(`
{"some_unknown_key":{"foo":1}}
{"finding":{"osv":"X","trace":[{"module":"m","package":"p","function":"f"}]}}
`)
	r, err := parseGovulncheckJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Findings["X"]; !ok {
		t.Errorf("expected finding X to survive unknown envelope: %+v", r.Findings)
	}
}
