package mcp

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestOverrideAdvicePerPackageManager(t *testing.T) {
	pkg := PackageIdentity{Name: "js-yaml", Version: "3.13.0", Purl: "pkg:npm/js-yaml@3.13.0"}
	cases := []struct {
		pm        string
		contains  []string
		supported bool
	}{
		// The issue #245 comment's example: "To fix js-yaml, add a pnpm
		// override in pnpm-workspace.yaml to 3.15.0."
		{"pnpm", []string{`"js-yaml": "3.15.0"`, "pnpm-workspace.yaml", "pnpm install"}, true},
		{"npm", []string{`"overrides"`, `"js-yaml": "3.15.0"`}, true},
		{"yarn", []string{`"resolutions"`, "yarn install"}, true},
		{"maven", []string{"<dependencyManagement>"}, true},
		{"gradle", []string{"constraints"}, true},
		{"gomod", []string{"go get js-yaml@v3.15.0", "go mod tidy"}, false},
		{"cargo", []string{"cargo update -p js-yaml --precise 3.15.0"}, false},
		{"pip", []string{"js-yaml>=3.15.0"}, true},
		{"poetry", []string{"pyproject.toml"}, true},
		{"bundler", []string{`gem "js-yaml"`}, true},
		{"composer", []string{"composer update js-yaml"}, true},
		{"conda", []string{"override mechanism"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.pm, func(t *testing.T) {
			advice, supported := overrideAdvice(tc.pm, pkg, "3.15.0", "pnpm-workspace.yaml")
			if supported != tc.supported {
				t.Fatalf("supported = %v, want %v", supported, tc.supported)
			}
			for _, want := range tc.contains {
				if !strings.Contains(advice, want) {
					t.Fatalf("advice %q does not contain %q", advice, want)
				}
			}
		})
	}
}

func TestTransitiveGoModuleGetsLockfileRefresh(t *testing.T) {
	in := remediationFixture(t)
	// Rebuild the deep transitive case as a Go module: gomod has no
	// declarative override, so the action must be lockfile-refresh with a
	// copy/paste go get command.
	in.Manifests[0].PackageManager = sdk.PackageManagerGoMod
	out := buildRemediations(in)
	refresh := groupByAction(t, out.Remediations, ActionLockfileRefresh)
	if refresh.TargetPackage.Name != "lib-b" {
		t.Fatalf("lockfile-refresh should target the direct ancestor, got %#v", refresh.TargetPackage)
	}
	if !strings.Contains(refresh.OverrideAdvice, "go get @scope/deep@v2.1.0") {
		t.Fatalf("expected go get advice, got %q", refresh.OverrideAdvice)
	}
	if !strings.Contains(refresh.Recommendation, "refresh the resolved version") {
		t.Fatalf("recommendation missing refresh wording: %q", refresh.Recommendation)
	}
}

func TestTransitiveOverrideCarriesAdvice(t *testing.T) {
	out := buildRemediations(remediationFixture(t))
	transitive := groupByAction(t, out.Remediations, ActionTransitiveOverride)
	if !strings.Contains(transitive.OverrideAdvice, `"@scope/deep": "2.1.0"`) {
		t.Fatalf("expected npm override advice with scoped name, got %q", transitive.OverrideAdvice)
	}
	if !strings.Contains(transitive.Recommendation, transitive.OverrideAdvice) {
		t.Fatalf("recommendation should embed the advice: %q", transitive.Recommendation)
	}
}
