package output

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

// TestDocumentCollectionsAreAlwaysArrays guards the standing rule in
// collections.go: no collection in the diff or explain document is
// omitted when empty, and none is written as null.
func TestDocumentCollectionsAreAlwaysArrays(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || typ.PkgPath() != documentPackage || seen[typ] {
			return
		}
		seen[typ] = true
		for i := range typ.NumField() {
			field := typ.Field(i)
			if field.Type.Kind() == reflect.Slice && strings.Contains(field.Tag.Get("json"), ",omitempty") {
				t.Errorf("%s.%s is a collection marked omitempty; document collections are always written", typ.Name(), field.Name)
			}
			walk(field.Type)
		}
	}
	walk(reflect.TypeFor[DiffResponse]())
	walk(reflect.TypeFor[ExplainResponse]())
	if len(seen) < 10 {
		t.Fatalf("walked only %d types; the walk is broken", len(seen))
	}

	// Empty documents, and documents whose nested elements are themselves
	// empty, encode no null.
	documents := map[string]any{
		"empty diff":    DiffResponse{},
		"empty explain": ExplainResponse{},
		"nested diff": DiffResponse{
			Packages: []*model.Package{{Coordinates: model.Coordinates{PURL: "pkg:npm/a@1.0.0"}}},
			Audit:    &DiffAudit{},
			Results: DiffResults{
				Dependencies:    DiffDependencyResults{Added: []DiffPackageChange{{}}, Transitions: []DiffDependencyTransition{{}}},
				Licenses:        DiffLicenseResults{Added: []DiffLicenseChange{{}}, Changed: []DiffLicenseDelta{{}}},
				Vulnerabilities: DiffVulnerabilityResults{Added: []DiffVulnerabilityChange{{}}},
				Manifests:       []DiffManifestResult{{}},
			},
		},
		"nested explain": ExplainResponse{Paths: []DependencyPath{{Packages: []PackageRef{{}}}}, Targets: []ExplainTargetResponse{{}}},
	}
	for name, document := range documents {
		data, err := json.Marshal(document)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(string(data), "null") {
			t.Errorf("%s encodes a null collection: %s", name, data)
		}
	}
	data, _ := json.Marshal(documents["empty diff"])
	// Audit is a pointer, absent when no audit ran; every collection that is
	// present is an array.
	for _, key := range []string{`"added":[]`, `"warnings":[]`, `"packages":[]`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("empty diff is missing %s: %s", key, data)
		}
	}
	data, _ = json.Marshal(documents["nested diff"])
	for _, key := range []string{`"introduced":[]`, `"licenses":[]`, `"vulnerabilities":[]`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("nested diff is missing %s: %s", key, data)
		}
	}
}
