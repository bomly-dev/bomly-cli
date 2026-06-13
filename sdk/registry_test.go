package sdk

import "testing"

func TestPackageRegistryUsesPURLAsDefaultPackageID(t *testing.T) {
	const purl = "pkg:npm/react@18.2.0"
	registry := NewPackageRegistry()

	ensured := registry.Ensure(purl)
	if ensured == nil {
		t.Fatal("Ensure() returned nil")
	}
	if ensured.ID != purl {
		t.Fatalf("Ensure() package ID = %q, want %q", ensured.ID, purl)
	}

	added := registry.Add(&Package{Coordinates: Coordinates{PURL: purl}})
	if added == nil {
		t.Fatal("Add() returned nil")
	}
	if added.ID != purl {
		t.Fatalf("Add() package ID = %q, want %q", added.ID, purl)
	}
}
