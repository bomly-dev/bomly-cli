package sdk

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPackageRemediationCloneAndJSON(t *testing.T) {
	original := &Package{
		Coordinates: Coordinates{PURL: "pkg:npm/example@1.0.0"},
		Remediation: &PackageRemediation{
			Status:             PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
		},
	}

	clone := original.Clone()
	if clone.Remediation == original.Remediation {
		t.Fatal("Clone() reused the remediation pointer")
	}
	clone.Remediation.RecommendedVersion = "2.0.0"
	if original.Remediation.RecommendedVersion != "1.2.0" {
		t.Fatalf("Clone() mutated original remediation: %#v", original.Remediation)
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	jsonValue := string(data)
	if !strings.Contains(jsonValue, `"remediation":{"status":"complete","recommended_version":"1.2.0"}`) {
		t.Fatalf("Marshal() omitted remediation fields: %s", data)
	}
}

func TestPackageRemediationJSONOmitsEmptyValues(t *testing.T) {
	data, err := json.Marshal(&Package{
		Coordinates: Coordinates{PURL: "pkg:npm/example@1.0.0"},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(data), `"remediation"`) {
		t.Fatalf("Marshal() included nil remediation: %s", data)
	}

	data, err = json.Marshal(&Package{
		Coordinates: Coordinates{PURL: "pkg:npm/example@1.0.0"},
		Remediation: &PackageRemediation{
			Status: PackageRemediationUnknown,
		},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(data), `"recommended_version"`) {
		t.Fatalf("Marshal() included empty recommended version: %s", data)
	}
}

func TestPackageRemediationKeepsProtocolV1PackageJSONCompatible(t *testing.T) {
	legacy := []byte(`{
		"purl":"pkg:npm/example@1.0.0",
		"name":"example",
		"version":"1.0.0",
		"vulnerabilities":[{"id":"GHSA-example","fixed_in":"1.2.0"}]
	}`)
	var pkg Package
	if err := json.Unmarshal(legacy, &pkg); err != nil {
		t.Fatalf("Unmarshal(legacy package) error = %v", err)
	}
	if pkg.Remediation != nil {
		t.Fatalf("legacy package unexpectedly gained remediation: %#v", pkg.Remediation)
	}

	pkg.Remediation = &PackageRemediation{
		Status:             PackageRemediationComplete,
		RecommendedVersion: "1.2.0",
	}
	current, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("Marshal(current package) error = %v", err)
	}
	var roundTrip Package
	if err := json.Unmarshal(current, &roundTrip); err != nil {
		t.Fatalf("Unmarshal(current package) error = %v", err)
	}
	if roundTrip.Remediation == nil ||
		roundTrip.Remediation.Status != PackageRemediationComplete ||
		roundTrip.Remediation.RecommendedVersion != "1.2.0" {
		t.Fatalf("current remediation did not round trip: %#v", roundTrip.Remediation)
	}
}
