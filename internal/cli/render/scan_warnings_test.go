package render

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	model "github.com/bomly-dev/bomly-sdk"
)

func fallbackWarnings() []model.DetectorWarning {
	return []model.DetectorWarning{{
		Type:     model.DetectorWarningFallback,
		Source:   "maven-detector",
		Manifest: "pom.xml",
		Message:  "maven-detector unavailable (not ready: java executable not found on PATH) — resolved with syft-detector; transitive dependencies may be missing",
	}}
}

func installGateWarnings() []model.DetectorWarning {
	warning := model.DetectorWarning{
		Type:     model.DetectorWarningPackageManager,
		Code:     model.DetectorWarningCodeInstallGate,
		Source:   "pnpm",
		Manifest: "pnpm-workspace.yaml",
		Message:  "pnpm-workspace.yaml sets minimumReleaseAge=1440 (24h); versions published inside that window are rejected at install",
	}
	second := warning
	second.Manifest = "packages/api/pnpm-workspace.yaml"
	return []model.DetectorWarning{warning, second}
}

func TestWarningNotices(t *testing.T) {
	notices := WarningNotices(fallbackWarnings())
	if len(notices) != 1 {
		t.Fatalf("expected 1 notice, got %#v", notices)
	}
	if !strings.Contains(notices[0], "maven-detector unavailable") ||
		!strings.Contains(notices[0], "transitive dependencies may be missing") {
		t.Fatalf("notice lost its content: %q", notices[0])
	}
	if !strings.Contains(notices[0], "(pom.xml)") {
		t.Fatalf("notice should name the file it came from: %q", notices[0])
	}
	if got := WarningNotices(nil); got != nil {
		t.Fatalf("expected nil for no warnings, got %#v", got)
	}
}

func TestWarningNotices_GroupsRepeatedWarnings(t *testing.T) {
	notices := WarningNotices(installGateWarnings())
	if len(notices) != 1 {
		t.Fatalf("expected the shared warning to collapse to 1 notice, got %#v", notices)
	}
	if !strings.Contains(notices[0], "pnpm-workspace.yaml, packages/api/pnpm-workspace.yaml") {
		t.Fatalf("notice should name every file it came from: %q", notices[0])
	}
}

func TestWarningNotices_CapsFanOut(t *testing.T) {
	warnings := make([]model.DetectorWarning, 0, 9)
	for idx := 0; idx < 9; idx++ {
		warnings = append(warnings, model.DetectorWarning{
			Type:     model.DetectorWarningFallback,
			Source:   "maven-detector",
			Manifest: fmt.Sprintf("module-%d/pom.xml", idx),
			Message:  "maven-detector unavailable (not ready) — resolved with syft-detector",
		})
	}
	notices := WarningNotices(warnings)
	if len(notices) != 1 {
		t.Fatalf("expected 1 grouped notice, got %#v", notices)
	}
	if !strings.Contains(notices[0], "+4 more") {
		t.Fatalf("expected capped path list with overflow count: %q", notices[0])
	}
	if strings.Contains(notices[0], "module-5/pom.xml") {
		t.Fatalf("expected paths past the cap to be omitted: %q", notices[0])
	}
}

func TestWarningNotices_StripsTerminalControlSequences(t *testing.T) {
	// Message and file text come from scanned repository content, so a crafted
	// package.json or filename must not be able to clear the screen, reposition
	// the cursor, or forge output once the notice is wrapped in Style().
	warnings := []model.DetectorWarning{{
		Type:     model.DetectorWarningPackageManager,
		Source:   "pnpm",
		Manifest: "\x1b[2Jpkg/\x1b]0;forged title\x07package.json",
		Message:  "engines mismatch\x1b[2J\x1b[1;1H✗ Bomly: no issues found\r\nforged",
	}}
	notices := WarningNotices(warnings)
	if len(notices) != 1 {
		t.Fatalf("expected 1 notice, got %#v", notices)
	}
	notice := notices[0]
	for _, forbidden := range []string{"\x1b", "\x07", "\r", "\n", "[2J", "[1;1H", "]0;"} {
		if strings.Contains(notice, forbidden) {
			t.Fatalf("notice must not carry %q: %q", forbidden, notice)
		}
	}
	// The readable text survives; only the control sequences are dropped.
	if !strings.Contains(notice, "engines mismatch") || !strings.Contains(notice, "package.json") {
		t.Fatalf("sanitizer dropped legitimate text: %q", notice)
	}
}

func TestSanitizeUntrusted(t *testing.T) {
	cases := map[string]string{
		"plain text":                   "plain text",
		"a\x1b[31mred\x1b[0mb":         "aredb",
		"osc\x1b]0;title\x07end":       "oscend",
		"st\x1b]8;;http://x\x1b\\link": "stlink",
		"tabs\tand\nnewlines":          "tabs and newlines",
		"nul\x00and\x7fdel":            "nulanddel",
		"trailing esc\x1b":             "trailing esc",
		"two char\x1b(Bescape":         "two charescape",
		"  collapsed   whitespace  ":   "collapsed whitespace",
	}
	for input, want := range cases {
		if got := SanitizeUntrusted(input); got != want {
			t.Fatalf("SanitizeUntrusted(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestScanRendersWarningNotices(t *testing.T) {
	g := model.New()
	if err := g.AddNode(model.NewDependencyRef("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}
	out := Scan(g, nil, nil, nil, false, false, false, nil, nil, WarningNotices(fallbackWarnings()))
	if !strings.Contains(out, "⚠ maven-detector unavailable") {
		t.Fatalf("expected fallback notice in scan text output, got:\n%s", out)
	}
	if !strings.Contains(out, "transitive dependencies may be missing") {
		t.Fatalf("expected consequence hint in scan text output, got:\n%s", out)
	}
}

func TestScanRendersWarningNoticesWithoutControlSequences(t *testing.T) {
	g := model.New()
	if err := g.AddNode(model.NewDependencyRef("app", "1.0.0")); err != nil {
		t.Fatalf("add node: %v", err)
	}
	warnings := []model.DetectorWarning{{
		Type:    model.DetectorWarningPackageManager,
		Source:  "pnpm",
		Message: "gate\x1b[2Jcleared the screen",
	}}
	out := Scan(g, nil, nil, nil, false, false, false, nil, nil, WarningNotices(warnings))
	if strings.Contains(out, "\x1b[2J") {
		t.Fatalf("scan output must not carry repository-supplied control sequences:\n%q", out)
	}
}

func TestScanMarkdownRendersWarning(t *testing.T) {
	payload := output.ScanResponse{
		Project:  output.ProjectDescriptor{Name: "demo"},
		Warnings: fallbackWarnings(),
	}
	var buf bytes.Buffer
	if err := ScanMarkdown(&buf, payload); err != nil {
		t.Fatalf("ScanMarkdown() error = %v", err)
	}
	if !strings.Contains(buf.String(), "> **Warning:** maven-detector unavailable") {
		t.Fatalf("expected warning block in markdown, got:\n%s", buf.String())
	}
}

func TestScanMarkdownEscapesUntrustedWarningText(t *testing.T) {
	payload := output.ScanResponse{
		Project: output.ProjectDescriptor{Name: "demo"},
		Warnings: []model.DetectorWarning{{
			Type:     model.DetectorWarningFallback,
			Source:   "maven-detector",
			Manifest: "<script>alert(1)</script>/pom.xml",
			Message:  "maven-detector unavailable (not ready: <img src=x onerror=alert(1)>)",
		}},
	}
	var buf bytes.Buffer
	if err := ScanMarkdown(&buf, payload); err != nil {
		t.Fatalf("ScanMarkdown() error = %v", err)
	}
	rendered := buf.String()
	if strings.Contains(rendered, "<script>") || strings.Contains(rendered, "<img") {
		t.Fatalf("expected untrusted warning text to be HTML-escaped in markdown, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "&lt;script&gt;") {
		t.Fatalf("expected escaped script tag in markdown output, got:\n%s", rendered)
	}
}
