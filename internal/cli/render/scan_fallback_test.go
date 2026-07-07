package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

func fallbackTestManifests() []output.ScanManifest {
	return []output.ScanManifest{
		{
			Path:     "pom.xml",
			Detector: "syft-detector",
			Resolution: &model.ResolutionMetadata{
				Fallback: &model.ResolutionFallback{From: "maven-detector", Reason: "not ready: java executable not found on PATH"},
			},
		},
		{
			Path:     "package-lock.json",
			Detector: "npm-lockfile",
		},
	}
}

func TestFallbackNotices(t *testing.T) {
	notices := FallbackNotices(fallbackTestManifests())
	if len(notices) != 1 {
		t.Fatalf("expected one notice, got %#v", notices)
	}
	want := "maven-detector unavailable (not ready: java executable not found on PATH) — resolved pom.xml with syft-detector; transitive dependencies may be missing"
	if notices[0] != want {
		t.Fatalf("unexpected notice:\n got %q\nwant %q", notices[0], want)
	}

	if got := FallbackNotices(fallbackTestManifests()[1:]); got != nil {
		t.Fatalf("expected no notices without fallback provenance, got %#v", got)
	}
}

func TestScanRendersFallbackNotices(t *testing.T) {
	g := model.New()
	if err := g.AddNode(model.NewDependencyRef("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}
	out := Scan(g, nil, nil, nil, false, false, false, nil, "", FallbackNotices(fallbackTestManifests()))
	if !strings.Contains(out, "⚠ maven-detector unavailable") {
		t.Fatalf("expected fallback notice in scan text output, got:\n%s", out)
	}
	if !strings.Contains(out, "transitive dependencies may be missing") {
		t.Fatalf("expected consequence hint in scan text output, got:\n%s", out)
	}
}

func TestScanMarkdownRendersFallbackWarning(t *testing.T) {
	payload := output.ScanResponse{
		Project:   output.ProjectDescriptor{Name: "demo"},
		Manifests: fallbackTestManifests(),
	}
	var buf bytes.Buffer
	if err := ScanMarkdown(&buf, payload); err != nil {
		t.Fatalf("ScanMarkdown() error = %v", err)
	}
	if !strings.Contains(buf.String(), "> **Warning:** maven-detector unavailable") {
		t.Fatalf("expected fallback warning block in markdown, got:\n%s", buf.String())
	}
}
