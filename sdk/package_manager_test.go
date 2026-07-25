package sdk

import (
	"encoding/json"
	"testing"
)

func TestPackageManagerParsingNameAndJSON(t *testing.T) {
	manager, err := ParsePackageManager(" NPM ")
	if err != nil {
		t.Fatalf("expected package manager name to parse: %v", err)
	}
	if manager != PackageManagerNPM {
		t.Fatalf("expected npm alias, got %q", manager.Name())
	}
	if got := manager.Name(); got != "npm" {
		t.Fatalf("expected canonical name npm, got %q", got)
	}
	if got := manager.String(); got != "npm" {
		t.Fatalf("expected string npm, got %q", got)
	}
	if got := manager.Ecosystem(); got != EcosystemNPM {
		t.Fatalf("expected npm ecosystem, got %q", got)
	}

	data, err := json.Marshal(manager)
	if err != nil {
		t.Fatalf("marshal package manager: %v", err)
	}
	if string(data) != `"npm"` {
		t.Fatalf("expected JSON name, got %s", data)
	}

	var decoded PackageManager
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal package manager: %v", err)
	}
	if decoded != PackageManagerNPM {
		t.Fatalf("expected decoded npm, got %q", decoded.Name())
	}
}

func TestOtherPackageManagerAndEcosystem(t *testing.T) {
	ecosystem, err := ParseEcosystem(" other ")
	if err != nil {
		t.Fatalf("parse other ecosystem: %v", err)
	}
	if ecosystem != EcosystemOther {
		t.Fatalf("expected other ecosystem, got %q", ecosystem)
	}

	manager, err := ParsePackageManager(" other ")
	if err != nil {
		t.Fatalf("parse other package manager: %v", err)
	}
	if manager != PackageManagerOther {
		t.Fatalf("expected other package manager, got %q", manager.Name())
	}
	if got := manager.Name(); got != "other" {
		t.Fatalf("expected canonical name other, got %q", got)
	}
	if got := manager.String(); got != "other" {
		t.Fatalf("expected string other, got %q", got)
	}
	if got := manager.Ecosystem(); got != EcosystemOther {
		t.Fatalf("expected other ecosystem, got %q", got)
	}

	data, err := json.Marshal(manager)
	if err != nil {
		t.Fatalf("marshal other package manager: %v", err)
	}
	if string(data) != `"other"` {
		t.Fatalf("expected JSON name, got %s", data)
	}
	var decoded PackageManager
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal other package manager: %v", err)
	}
	if decoded != PackageManagerOther {
		t.Fatalf("expected decoded other, got %q", decoded.Name())
	}
}

func TestScalaPackageManagerAndEcosystem(t *testing.T) {
	ecosystem, err := ParseEcosystem(" scala ")
	if err != nil {
		t.Fatalf("parse scala ecosystem: %v", err)
	}
	if ecosystem != EcosystemScala {
		t.Fatalf("expected scala ecosystem, got %q", ecosystem)
	}

	manager, err := ParsePackageManager(" sbt ")
	if err != nil {
		t.Fatalf("parse sbt package manager: %v", err)
	}
	if manager != PackageManagerSBT {
		t.Fatalf("expected sbt package manager, got %q", manager.Name())
	}
	if got := manager.Ecosystem(); got != EcosystemScala {
		t.Fatalf("expected scala ecosystem, got %q", got)
	}
}

func TestBuildPackageURLFallbackForSwift(t *testing.T) {
	got := BuildPackageURL("swift", "", "async-kit", "1.15.0")
	if got != "pkg:swift/async-kit@1.15.0" {
		t.Fatalf("expected Swift package URL, got %q", got)
	}
}

func TestCanonicalizePackageURLNormalizesNPMScopes(t *testing.T) {
	tests := map[string]string{
		"pkg:npm/google-cloud/common@0.12.0":    "pkg:npm/%40google-cloud/common@0.12.0",
		"pkg:npm/%40google-cloud/common@0.12.0": "pkg:npm/%40google-cloud/common@0.12.0",
	}
	for input, want := range tests {
		if got := CanonicalizePackageURL(input); got != want {
			t.Fatalf("CanonicalizePackageURL(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestBuildPackageURLNormalizesNPMScopes(t *testing.T) {
	got := BuildPackageURL("npm", "google-cloud", "common", "0.12.0")
	if got != "pkg:npm/%40google-cloud/common@0.12.0" {
		t.Fatalf("expected scoped npm package URL, got %q", got)
	}
}

func TestPackageURLTypeForGitHubActions(t *testing.T) {
	if got := PackageURLTypeForValues("github-actions"); got != "githubactions" {
		t.Fatalf("expected GitHub Actions PURL type, got %q", got)
	}
}

// Every declared ecosystem must resolve to a type that exists in the purl spec.
// Without an explicit case the fallback returns the Bomly identifier verbatim,
// which produced pkg:erlang / pkg:haskell / pkg:r / pkg:ocaml / pkg:dpkg and
// made those packages unmatchable downstream. See issue #317.
func TestPackageURLTypeForValuesUsesSpecTypes(t *testing.T) {
	cases := []struct {
		ecosystem Ecosystem
		manager   PackageManager
		want      string
	}{
		{EcosystemErlang, PackageManagerRebar, "hex"},
		{EcosystemElixir, PackageManagerMix, "hex"},
		// OTP applications ship with the runtime rather than resolving from
		// Hex, so they must not be claimed as Hex packages: a name collision
		// with a real Hex package would produce a false advisory match.
		{EcosystemErlang, PackageManagerOTP, "otp"},
		{EcosystemHaskell, PackageManagerCabal, "hackage"},
		{EcosystemHaskell, PackageManagerStack, "hackage"},
		{EcosystemR, PackageManagerRPackage, "cran"},
		{EcosystemOCaml, PackageManagerOpam, "opam"},
		{EcosystemDPKG, PackageManagerDPKG, "deb"},

		// Regression guards for the ecosystems that already mapped correctly.
		{EcosystemNPM, PackageManagerNPM, "npm"},
		{EcosystemGo, PackageManagerGoMod, "golang"},
		{EcosystemPython, PackageManagerPip, "pypi"},
		{EcosystemMaven, PackageManagerMaven, "maven"},
		{EcosystemScala, PackageManagerSBT, "maven"},
		{EcosystemRust, PackageManagerCargo, "cargo"},
		{EcosystemRuby, PackageManagerBundler, "gem"},
		{EcosystemPHP, PackageManagerComposer, "composer"},
		{EcosystemDotNet, PackageManagerNuGet, "nuget"},
		{EcosystemDart, PackageManagerPub, "pub"},
		{EcosystemSwift, PackageManagerSwiftPM, "swift"},
		{EcosystemSwift, PackageManagerCocoaPods, "cocoapods"},
		{EcosystemCPP, PackageManagerConan, "conan"},
		{EcosystemAPK, PackageManagerAPK, "apk"},
		{EcosystemRPM, PackageManagerRPM, "rpm"},
		{EcosystemGitHub, PackageManagerGitHubActions, "githubactions"},
	}

	for _, tc := range cases {
		if got := PackageURLTypeForValues(tc.ecosystem, tc.manager); got != tc.want {
			t.Errorf("PackageURLTypeForValues(%q, %q) = %q, want %q", tc.ecosystem, tc.manager, got, tc.want)
		}
	}
}

// The package manager is not always populated (SBOM ingest, syft-sourced
// container packages), so for ecosystems backed by a single registry the
// ecosystem alone has to be enough to reach a purl type in the spec.
//
// The exceptions are the ecosystems that span two registries, where the
// package manager is the only thing that says which one applies: swift covers
// SwiftPM and CocoaPods, erlang covers Hex and OTP. Guessing for those would
// name a registry the package may not be published to.
func TestPackageURLTypeForEcosystemAlone(t *testing.T) {
	multiRegistry := map[Ecosystem]bool{
		EcosystemSwift:  true,
		EcosystemErlang: true,
	}
	specTypes := map[string]bool{
		"apk": true, "cargo": true, "cocoapods": true, "composer": true,
		"conan": true, "cran": true, "deb": true, "gem": true,
		"githubactions": true, "golang": true, "hackage": true, "hex": true,
		"maven": true, "npm": true, "nuget": true, "opam": true, "otp": true,
		"pub": true, "pypi": true, "rpm": true, "swift": true,
	}

	for _, manager := range AllPackageManagers() {
		ecosystem := manager.Ecosystem()
		if multiRegistry[ecosystem] {
			continue
		}
		withManager := PackageURLTypeForValues(ecosystem, manager)
		if !specTypes[withManager] {
			// Ecosystems Bomly reports but the purl spec has no type for
			// (conda, homebrew, nix, ...) are out of scope here.
			continue
		}
		if got := PackageURLTypeForValues(ecosystem); got != withManager {
			t.Errorf("PackageURLTypeForValues(%q) = %q, want %q (as with manager %q)", ecosystem, got, withManager, manager)
		}
	}
}

func TestAllPackageManagersReturnsCopy(t *testing.T) {
	managers := AllPackageManagers()
	if len(managers) == 0 {
		t.Fatal("expected package managers")
	}

	original := AllPackageManagers()[0]
	managers[0] = PackageManagerUnknown

	if got := AllPackageManagers()[0]; got != original {
		t.Fatalf("expected AllPackageManagers to return a copy, got %q want %q", got.Name(), original.Name())
	}
}
