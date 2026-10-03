package output

import (
	"encoding/json"
	"reflect"
	"strings"

	"github.com/bomly-dev/bomly-sdk/scan"
)

// Collections in the CLI's JSON documents are always written, as [] when
// empty, never omitted and never null. A user's automation iterates them
// (`.audit.introduced[]`, `.results.dependencies.added[]`, `.paths[]`), and
// a missing key or a null breaks that iteration on exactly the run that
// found nothing. An empty array and an absent key mean the same thing here
// -- none recorded -- so the array adds no claim; it only keeps the shape
// stable. This is a standing project decision, shared with the SDK's scan
// record (scan.IteratedCollections); TestDocumentCollectionsAreAlwaysArrays
// guards it. SARIF is out of scope: it is a format with its own
// specification, not one of these documents.

// fillEmptyCollections walks a document value in place and replaces every
// nil slice held by a struct this package defines with an empty one, so it
// encodes as [] rather than null. Types from other packages are not
// entered: the SDK's own document types write their collections
// themselves, and the model's wire types are optional by contract.
func fillEmptyCollections(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			fillEmptyCollections(v.Elem())
		}
	case reflect.Slice:
		for i := range v.Len() {
			fillEmptyCollections(v.Index(i))
		}
	case reflect.Struct:
		if v.Type().PkgPath() != documentPackage {
			return
		}
		for i := range v.NumField() {
			field, value := v.Type().Field(i), v.Field(i)
			if !field.IsExported() || !value.CanSet() {
				continue
			}
			if value.Kind() == reflect.Slice && value.IsNil() && writesCollection(field) {
				value.Set(reflect.MakeSlice(value.Type(), 0, 0))
				continue
			}
			fillEmptyCollections(value)
		}
	}
}

// writesCollection reports whether a field is encoded under a key at all.
func writesCollection(field reflect.StructField) bool {
	tag := field.Tag.Get("json")
	return tag != "-" && !strings.Contains(tag, ",omitempty")
}

var documentPackage = reflect.TypeFor[DiffResponse]().PkgPath()

// MarshalJSON writes the diff document with every collection present, and
// each package with its licenses and vulnerabilities written as [] when it
// has none (scan.Package). The receiver is a copy; only nil slices are
// replaced, which encodes the same value the holder already has.
func (r DiffResponse) MarshalJSON() ([]byte, error) {
	type plain DiffResponse
	fillEmptyCollections(reflect.ValueOf(&r).Elem())
	return json.Marshal(struct {
		plain
		Packages []scan.Package `json:"packages"`
	}{plain: plain(r), Packages: scan.Packages(r.Packages)})
}

// MarshalJSON writes the explain document with every collection present.
func (r ExplainResponse) MarshalJSON() ([]byte, error) {
	type plain ExplainResponse
	fillEmptyCollections(reflect.ValueOf(&r).Elem())
	return json.Marshal(plain(r))
}
