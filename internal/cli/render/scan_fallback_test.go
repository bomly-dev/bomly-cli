package render

import (
	"bytes"
	"fmt"
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

func TestFallbackNotices_GroupsAndCapsFanOut(t *testing.T) {
	manifests := make([]output.ScanManifest, 0, 8)
	for i := 0; i < 8; i++ {
		manifests = append(manifests, output.ScanManifest{
			Path:     fmt.Sprintf("modules/m%d/pom.xml", i),
			Detector: "syft-detector",
			Resolution: &model.ResolutionMetadata{
				Fallback: &model.ResolutionFallback{From: "maven-detector", Reason: "not ready: java executable not found on PATH"},
			},
		})
	}
	notices := FallbackNotices(manifests)
	if len(notices) != 1 {
		t.Fatalf("expected a single grouped notice for a shared fallback cause, got %#v", notices)
	}
	notice := notices[0]
	if !strings.Contains(notice, "resolved 8 manifests with syft-detector") {
		t.Fatalf("expected grouped manifest count in notice, got %q", notice)
	}
	if !strings.Contains(notice, "+3 more") {
		t.Fatalf("expected overflow count capping the path list, got %q", notice)
	}
	if strings.Count(notice, "modules/m") != maxFallbackNoticePaths {
		t.Fatalf("expected only %d example paths listed, got %q", maxFallbackNoticePaths, notice)
	}
}

func TestFallbackNotices_CollapsesEmbeddedNewlines(t *testing.T) {
	manifests := []output.ScanManifest{{
		Path:     "weird\npath/pom.xml",
		Detector: "syft-detector",
		Resolution: &model.ResolutionMetadata{
			Fallback: &model.ResolutionFallback{From: "maven-detector", Reason: "not ready:\njava missing"},
		},
	}}
	notices := FallbackNotices(manifests)
	if len(notices) != 1 {
		t.Fatalf("expected one notice, got %#v", notices)
	}
	if strings.Contains(notices[0], "\n") {
		t.Fatalf("expected no embedded newlines in notice, got %q", notices[0])
	}
}

func TestScanRendersFallbackNotices(t *testing.T) {
	g := model.New()
	if err := g.AddNode(model.NewDependencyRef("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}
	out := Scan(g, nil, nil, nil, false, false, false, nil, nil, FallbackNotices(fallbackTestManifests()))
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

func TestScanMarkdownEscapesUntrustedFallbackText(t *testing.T) {
	payload := output.ScanResponse{
		Project: output.ProjectDescriptor{Name: "demo"},
		Manifests: []output.ScanManifest{{
			Path:     "<script>alert(1)</script>/pom.xml",
			Detector: "syft-detector",
			Resolution: &model.ResolutionMetadata{
				Fallback: &model.ResolutionFallback{From: "maven-detector", Reason: "not ready: <img src=x onerror=alert(1)>"},
			},
		}},
	}
	var buf bytes.Buffer
	if err := ScanMarkdown(&buf, payload); err != nil {
		t.Fatalf("ScanMarkdown() error = %v", err)
	}
	rendered := buf.String()
	if strings.Contains(rendered, "<script>") || strings.Contains(rendered, "<img") {
		t.Fatalf("expected untrusted manifest path/reason to be HTML-escaped in markdown, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "&lt;script&gt;") {
		t.Fatalf("expected escaped script tag in markdown output, got:\n%s", rendered)
	}
}

func resolutionWarningManifests() []output.ScanManifest {
	warning := model.ResolutionWarning{
		Code:    model.ResolutionWarningInstallGate,
		Source:  "pnpm",
		Message: "pnpm-workspace.yaml sets minimumReleaseAge=1440 (24h); versions published inside that window are rejected at install",
	}
	return []output.ScanManifest{
		{Path: "pnpm-lock.yaml", Resolution: &model.ResolutionMetadata{Warnings: []model.ResolutionWarning{warning}}},
		{Path: "packages/api/package.json", Resolution: &model.ResolutionMetadata{Warnings: []model.ResolutionWarning{warning}}},
		{Path: "packages/web/package.json"},
	}
}

func TestResolutionWarningNotices_GroupsRepeatedWarnings(t *testing.T) {
	notices := ResolutionWarningNotices(resolutionWarningManifests())
	if len(notices) != 1 {
		t.Fatalf("expected the shared warning to collapse to 1 notice, got %#v", notices)
	}
	if !strings.Contains(notices[0], "minimumReleaseAge=1440") {
		t.Fatalf("notice lost its message: %q", notices[0])
	}
	if !strings.Contains(notices[0], "pnpm-lock.yaml, packages/api/package.json") {
		t.Fatalf("notice should name the manifests it came from: %q", notices[0])
	}
	if got := ResolutionWarningNotices(resolutionWarningManifests()[2:]); got != nil {
		t.Fatalf("expected nil for manifests without warnings, got %#v", got)
	}
}

func TestResolutionWarningNotices_CollapsesEmbeddedNewlines(t *testing.T) {
	manifests := []output.ScanManifest{{
		Path: "pnpm-lock.yaml",
		Resolution: &model.ResolutionMetadata{Warnings: []model.ResolutionWarning{{
			Code:    model.ResolutionWarningEngines,
			Message: "engines mismatch\n\n✗ injected line",
		}}},
	}}
	notices := ResolutionWarningNotices(manifests)
	if len(notices) != 1 {
		t.Fatalf("expected 1 notice, got %#v", notices)
	}
	if strings.Contains(notices[0], "\n") {
		t.Fatalf("notice must stay single-line: %q", notices[0])
	}
}

func TestScanRendersResolutionWarningNotices(t *testing.T) {
	g := model.New()
	if err := g.AddNode(model.NewDependencyRef("react", "18.2.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}
	manifests := resolutionWarningManifests()
	out := Scan(g, nil, nil, nil, false, false, false, nil, manifests, ResolutionWarningNotices(manifests))
	if !strings.Contains(out, "minimumReleaseAge=1440") {
		t.Fatalf("scan report is missing the resolution warning:\n%s", out)
	}
}
