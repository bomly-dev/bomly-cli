package cli

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/config"
)

func TestApplyStringOverride(t *testing.T) {
	value := "original"
	applyStringOverride(&value, "")
	if value != "original" {
		t.Fatalf("empty override changed value to %q", value)
	}

	applyStringOverride(&value, "updated")
	if value != "updated" {
		t.Fatalf("expected updated value, got %q", value)
	}
}

func TestCloneWithOverridesAppliesRecursiveDiscovery(t *testing.T) {
	adapter := &mcpOptionsAdapter{options: opts.NewOptions()}
	base := adapter.options.GetConfig()
	config.ApplyDefaults(&base)
	adapter.options.SetConfig(base)

	clone := adapter.cloneWithOverrides(mcpOverrides{
		Recursive: true,
		MaxDepth:  5,
		Exclude:   "apps/*, dist",
	})
	got := clone.GetConfig()
	if !got.Recursive {
		t.Fatal("expected recursive override to apply")
	}
	if got.MaxDepth != 5 {
		t.Fatalf("expected max depth 5, got %d", got.MaxDepth)
	}
	if len(got.ExcludePaths) != 2 || got.ExcludePaths[0] != "apps/*" || got.ExcludePaths[1] != "dist" {
		t.Fatalf("expected CSV exclude override, got %#v", got.ExcludePaths)
	}

	// Zero MaxDepth means "not set": the server's resolved default survives.
	clone = adapter.cloneWithOverrides(mcpOverrides{Recursive: true})
	if got := clone.GetConfig(); got.MaxDepth != base.MaxDepth {
		t.Fatalf("expected default max depth %d to survive, got %d", base.MaxDepth, got.MaxDepth)
	}
}

func TestCloneWithOverridesAppliesPolicyControls(t *testing.T) {
	adapter := &mcpOptionsAdapter{options: opts.NewOptions()}
	base := adapter.options.GetConfig()
	config.ApplyDefaults(&base)
	adapter.options.SetConfig(base)

	clone := adapter.cloneWithOverrides(mcpOverrides{
		FailOn:                "high",
		AllowVulnerabilityIDs: "GHSA-one,CVE-2026-0001",
		AllowLicenses:         "MIT,Apache-2.0",
		DenyLicenses:          "AGPL-3.0-only",
		LicenseExemptPackages: "pkg:npm/example",
		DenyPackages:          "pkg:npm/blocked",
		DenyGroups:            "pkg:maven/com.example",
		ProtectedPackages:     "react,express",
		TyposquatThreshold:    "0.93",
		TyposquatMode:         "fail",
		WarnOnly:              true,
		Baseline:              "security/baseline.json",
	})
	got := clone.GetConfig()
	if !got.WarnOnly {
		t.Fatal("expected warn-only override")
	}
	if got.Baseline != "security/baseline.json" {
		t.Fatalf("baseline override = %q", got.Baseline)
	}
	assertStrings := func(name string, got, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s = %#v, want %#v", name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s = %#v, want %#v", name, got, want)
			}
		}
	}
	assertStrings("fail on", got.FailOn, []string{"high"})
	assertStrings("allow vulnerability IDs", got.AllowVulnerabilityIDs, []string{"GHSA-one", "CVE-2026-0001"})
	assertStrings("allow licenses", got.AllowLicenses, []string{"MIT", "Apache-2.0"})
	assertStrings("deny licenses", got.DenyLicenses, []string{"AGPL-3.0-only"})
	assertStrings("license exemptions", got.LicenseExemptPackages, []string{"pkg:npm/example"})
	assertStrings("deny packages", got.DenyPackages, []string{"pkg:npm/blocked"})
	assertStrings("deny groups", got.DenyGroups, []string{"pkg:maven/com.example"})
	assertStrings("protected packages", got.ProtectedPackages, []string{"react", "express"})
	if got.TyposquatThreshold != "0.93" || got.TyposquatMode != "fail" {
		t.Fatalf("typosquat overrides = threshold %q, mode %q", got.TyposquatThreshold, got.TyposquatMode)
	}
	if got.Enrich || got.Audit || got.Analyze {
		t.Fatal("policy-only overrides must not implicitly enable enrich, audit, or analyze")
	}
}

func TestValidatedCloneWithOverridesRejectsInvalidCombinations(t *testing.T) {
	adapter := &mcpOptionsAdapter{options: opts.NewOptions()}
	base := adapter.options.GetConfig()
	config.ApplyDefaults(&base)
	adapter.options.SetConfig(base)

	if _, err := adapter.validatedCloneWithOverrides(mcpOverrides{Exclude: "apps/*"}); err == nil {
		t.Fatal("expected exclude without recursive to fail validation")
	}
	if _, err := adapter.validatedCloneWithOverrides(mcpOverrides{Recursive: true, Image: "alpine:latest"}); err == nil {
		t.Fatal("expected recursive with image to fail validation")
	}
	if _, err := adapter.validatedCloneWithOverrides(mcpOverrides{Recursive: true, MaxDepth: 4}); err != nil {
		t.Fatalf("expected valid recursive overrides to pass, got %v", err)
	}
	if _, err := adapter.validatedCloneWithOverrides(mcpOverrides{TyposquatMode: "bogus"}); err == nil {
		t.Fatal("expected invalid typosquat mode to fail validation")
	}
	if _, err := adapter.validatedCloneWithOverrides(mcpOverrides{TyposquatThreshold: "not-a-number"}); err == nil {
		t.Fatal("expected non-numeric typosquat threshold to fail validation")
	}
}
