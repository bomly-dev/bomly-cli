package cli

import (
	"strings"
	"testing"

	"github.com/bomly/bomly-cli/internal/explain"
	"github.com/bomly/bomly-cli/internal/output"
)

func TestWhyTreeLines_RendersBranchingPaths(t *testing.T) {
	paths := []explain.Path{
		{
			Relationship: "transitive",
			Packages: []output.PackageRef{
				{ID: "app"},
				{ID: "react"},
				{ID: "loose-envify"},
			},
		},
		{
			Relationship: "transitive",
			Packages: []output.PackageRef{
				{ID: "app"},
				{ID: "zod"},
				{ID: "loose-envify"},
			},
		},
	}

	got := strings.Join(whyTreeLines(paths), "\n")
	want := strings.Join([]string{
		"app",
		"|- react",
		"|  \\- loose-envify (transitive)",
		"\\- zod",
		"   \\- loose-envify (transitive)",
	}, "\n")
	if got != want {
		t.Fatalf("whyTreeLines() mismatch\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func TestWhyTreeLines_PreservesLeafAnnotationsOnSharedPrefix(t *testing.T) {
	paths := []explain.Path{
		{
			Relationship: "direct",
			Packages: []output.PackageRef{
				{ID: "app"},
				{ID: "b"},
			},
		},
		{
			Relationship: "transitive",
			Cyclic:       true,
			CycleTo:      "b",
			Packages: []output.PackageRef{
				{ID: "app"},
				{ID: "b"},
				{ID: "c"},
				{ID: "b"},
			},
		},
	}

	got := strings.Join(whyTreeLines(paths), "\n")
	want := strings.Join([]string{
		"app",
		"\\- b (direct)",
		"   \\- c",
		"      \\- b (transitive, cycle to b)",
	}, "\n")
	if got != want {
		t.Fatalf("whyTreeLines() mismatch\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}
