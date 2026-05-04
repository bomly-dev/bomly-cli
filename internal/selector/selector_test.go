package selector

import (
	"errors"
	"reflect"
	"testing"
)

func TestResolve_Empty_ImplicitAll(t *testing.T) {
	catalog := Catalog{Kind: "x", Available: []string{"a", "b"}, AliasToName: map[string]string{"a": "a", "b": "b"}, Items: []string{"a", "b"}}
	include, exclude, err := Resolve("", []string{"a"}, catalog, true)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if include != nil || exclude != nil {
		t.Fatalf("expected nil/nil for implicit-all empty, got include=%v exclude=%v", include, exclude)
	}
}

func TestResolve_Empty_ExplicitDefaults(t *testing.T) {
	catalog := Catalog{Kind: "x", Available: []string{"a", "b", "c"}, AliasToName: map[string]string{"a": "a", "b": "b", "c": "c"}, Items: []string{"a", "b", "c"}}
	_, exclude, err := Resolve("", []string{"a"}, catalog, false)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	want := []string{"b", "c"}
	if !reflect.DeepEqual(exclude, want) {
		t.Fatalf("expected exclude %v, got %v", want, exclude)
	}
}

func TestResolve_Operators(t *testing.T) {
	catalog := Catalog{Kind: "x", Available: []string{"a", "b", "c"}, AliasToName: map[string]string{"a": "a", "b": "b", "c": "c"}, Items: []string{"a", "b", "c"}}
	_, exclude, err := Resolve("-b", []string{"a", "b"}, catalog, true)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	want := []string{"b", "c"}
	if !reflect.DeepEqual(exclude, want) {
		t.Fatalf("expected exclude %v, got %v", want, exclude)
	}
}

func TestResolve_PlainTokenReplaces(t *testing.T) {
	catalog := Catalog{Kind: "x", Available: []string{"a", "b"}, AliasToName: map[string]string{"a": "a", "b": "b", "alpha": "a"}, Items: []string{"a", "b"}}
	include, _, err := Resolve("alpha", []string{"a", "b"}, catalog, true)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	want := []string{"a"}
	if !reflect.DeepEqual(include, want) {
		t.Fatalf("expected include %v, got %v", want, include)
	}
}

func TestResolve_UnknownReturnsTypedError(t *testing.T) {
	catalog := Catalog{Kind: "ecosystem", Available: []string{"npm"}, AliasToName: map[string]string{"npm": "npm"}, Items: []string{"npm"}}
	_, _, err := Resolve("not-a-thing", nil, catalog, false)
	if err == nil {
		t.Fatal("expected error")
	}
	var unknown *UnknownSelectorError
	if !errors.As(err, &unknown) {
		t.Fatalf("expected *UnknownSelectorError, got %T", err)
	}
	if unknown.Kind != "ecosystem" {
		t.Fatalf("expected kind ecosystem, got %q", unknown.Kind)
	}
	if len(unknown.Unknown) != 1 || unknown.Unknown[0] != "not-a-thing" {
		t.Fatalf("expected unknown=[not-a-thing], got %v", unknown.Unknown)
	}
}

func TestParseCSV(t *testing.T) {
	got := ParseCSV("  a , b ,  ,c")
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	if ParseCSV("") != nil {
		t.Fatal("expected nil for empty input")
	}
}

func TestAppendUniqueAndContains(t *testing.T) {
	values := AppendUnique(nil, "a")
	values = AppendUnique(values, "a")
	values = AppendUnique(values, "b")
	if !reflect.DeepEqual(values, []string{"a", "b"}) {
		t.Fatalf("AppendUnique produced %v", values)
	}
	if !Contains(values, "a") || Contains(values, "missing") {
		t.Fatal("Contains returned wrong result")
	}
}
