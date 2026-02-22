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
