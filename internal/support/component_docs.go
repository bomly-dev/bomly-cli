package support

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/registry"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// RenderDetectorsOverviewMarkdown renders the human-readable detector guide.
func RenderDetectorsOverviewMarkdown() string {
	return strings.TrimSpace(`# Detectors

Detectors are the part of Bomly that read a project, container, or SBOM and turn the evidence into a dependency graph.

Bomly plans detector work before a scan starts. It looks for package-manager evidence such as lockfiles, manifests, workflow files, or SBOM documents, then runs the best detector chain for each discovered subproject. Native detectors run first when Bomly can produce a richer graph itself. Syft-backed detection fills coverage gaps and container/image scenarios.

## When Detectors Run

- `+"`bomly scan`"+` runs detectors to build the graph.
- `+"`bomly explain`"+` reuses the same detector planning before finding dependency paths.
- `+"`bomly diff`"+` runs detectors for each side of the comparison unless you diff SBOM files.
- Detector plugins participate in the same planning flow when they declare package-manager evidence.

## Detector Chains

A detector chain is the ordered list Bomly tries for a package manager. The first detector is preferred. A later detector is a fallback when the preferred detector is not ready, not applicable, or cannot produce graph data.

Some detectors can run an ecosystem tool such as `+"`npm`"+`, `+"`go`"+`, `+"`mvn`"+`, `+"`dart`"+`, `+"`swift`"+`, or `+"`sbt`"+`. Bomly does not install package managers for you. Use `+"`--install-first`"+` only when you want detectors that support it to run their normal dependency-install command before resolving the graph.

## Generated Ecosystem Guides

The pages in `+"`docs/detectors/ecosystems/`"+` are generated from Bomly's registry. Each page lists supported package managers, evidence patterns, chain order, install-first support, and the native commands users may need on `+"`PATH`"+`.
`) + "\n"
}

// RenderMatchersOverviewMarkdown renders the human-readable matcher guide.
func RenderMatchersOverviewMarkdown() string {
	return strings.TrimSpace(`# Matchers

Matchers enrich packages after Bomly has built a dependency graph.

Bomly is offline-safe by default. Network-backed matchers only run when package enrichment is explicitly enabled, for example with `+"`bomly scan --enrich`"+`. Matchers attach data such as vulnerabilities, license metadata, and end-of-life signals to packages. Auditors can then evaluate the enriched graph when `+"`--audit`"+` is enabled.

## What Matchers Add

- Vulnerability matchers add vulnerability IDs, severity, aliases, CVSS, fixed versions, references, and KEV signals where available.
- License matchers add license evidence from external package metadata services.
- Lifecycle matchers add ecosystem/runtime end-of-life metadata.

## Generated Matcher Guides

The pages in `+"`docs/matchers/`"+` are generated from Bomly's matcher descriptors and known runtime behavior. They list when each matcher runs, whether it uses the network, cache expectations, and the output fields users should expect.
`) + "\n"
}

// RenderAuditorsOverviewMarkdown renders the human-readable auditor guide.
func RenderAuditorsOverviewMarkdown() string {
	return strings.TrimSpace(`# Auditors

Auditors evaluate a graph and produce findings.

The default policy auditor looks at vulnerability data that is already present on packages. It does not make network calls on its own. If you want Bomly to fetch vulnerability data and then evaluate policy in one command, run `+"`bomly scan --enrich --audit`"+`.

## When Auditors Run

- `+"`bomly scan --audit`"+` evaluates the full graph.
- `+"`bomly explain --audit`"+` evaluates the selected component context.
- `+"`bomly diff --audit`"+` classifies introduced, resolved, and persisted findings.

## Findings

Findings have a normalized shape: ID, kind, severity, package, title, reasons, and source. Text output summarizes them for humans, JSON exposes them for automation, and SARIF is available for audit results with `+"`--format sarif`"+`.
`) + "\n"
}

// WriteComponentDocs writes generated detector and matcher documentation.
func WriteComponentDocs(docsDir string) error {
	files := map[string]string{
		filepath.Join(docsDir, "DETECTORS.md"): RenderDetectorsOverviewMarkdown(),
		filepath.Join(docsDir, "MATCHERS.md"):  RenderMatchersOverviewMarkdown(),
		filepath.Join(docsDir, "AUDITORS.md"):  RenderAuditorsOverviewMarkdown(),
	}
	for path, content := range files {
		if err := writeMarkdown(path, content); err != nil {
			return err
		}
	}
	if err := writeDetectorEcosystemDocs(filepath.Join(docsDir, "detectors", "ecosystems")); err != nil {
		return err
	}
	if err := writeMatcherDocs(filepath.Join(docsDir, "matchers")); err != nil {
		return err
	}
	return nil
}

func writeDetectorEcosystemDocs(outputDir string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", outputDir, err)
	}
	entries := registry.SupportEntries()
	byEcosystem := make(map[sdk.Ecosystem][]registry.PackageManagerSupport)
	for _, entry := range entries {
		byEcosystem[entry.Ecosystem] = append(byEcosystem[entry.Ecosystem], entry)
	}
	ecosystems := make([]sdk.Ecosystem, 0, len(byEcosystem))
	for ecosystem := range byEcosystem {
		ecosystems = append(ecosystems, ecosystem)
	}
	sort.Slice(ecosystems, func(i, j int) bool { return ecosystems[i] < ecosystems[j] })
	for _, ecosystem := range ecosystems {
		if err := writeMarkdown(filepath.Join(outputDir, string(ecosystem)+".md"), renderDetectorEcosystemMarkdown(ecosystem, byEcosystem[ecosystem])); err != nil {
			return err
		}
	}
	return writeMarkdown(filepath.Join(outputDir, "README.md"), renderDetectorEcosystemIndex(ecosystems))
}

func renderDetectorEcosystemIndex(ecosystems []sdk.Ecosystem) string {
	var b strings.Builder
	b.WriteString("# Detector Ecosystem Guides\n\n")
	b.WriteString("These generated pages explain how Bomly detects each supported ecosystem.\n\n")
	for _, ecosystem := range ecosystems {
		fmt.Fprintf(&b, "- [%s](%s.md)\n", ecosystem, ecosystem)
	}
	return b.String()
}

func renderDetectorEcosystemMarkdown(ecosystem sdk.Ecosystem, entries []registry.PackageManagerSupport) string {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Manager.Name() < entries[j].Manager.Name() })
	var b strings.Builder
	fmt.Fprintf(&b, "# %s Detectors\n\n", titleWords(string(ecosystem)))
	b.WriteString("<!-- Auto-generated by make generate. Do not edit manually. -->\n\n")
	fmt.Fprintf(&b, "Bomly uses these detector chains when it finds `%s` package-manager evidence.\n\n", ecosystem)
	b.WriteString("| Package manager | Detector chain | Evidence patterns | Install-first support | Native command hints |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, entry := range entries {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
			entry.Manager.Name(),
			codeList(entry.Detectors),
			codeListOrDash(entry.EvidencePatterns),
			yesNo(chainSupportsInstallFirst(entry.Detectors)),
			commandHintsForChain(entry.Detectors),
		)
	}
	b.WriteString("\n## How To Read This\n\n")
	b.WriteString("- Bomly tries detector chains from left to right.\n")
	b.WriteString("- Evidence patterns are files or paths Bomly uses during planning.\n")
	b.WriteString("- Install-first support means `--install-first` can run the ecosystem's normal install command before graph resolution.\n")
	b.WriteString("- Syft-backed entries provide broad compatibility, especially for containers and ecosystems without native Bomly graph resolution.\n")
	return b.String()
}

func writeMatcherDocs(outputDir string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", outputDir, err)
	}
	reg := registry.NewRegistry(registry.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	descriptors := reg.MatcherDescriptors()
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].Name < descriptors[j].Name })
	for _, descriptor := range descriptors {
		if err := writeMarkdown(filepath.Join(outputDir, descriptor.Name+".md"), renderMatcherMarkdown(descriptor)); err != nil {
			return err
		}
	}
	return writeMarkdown(filepath.Join(outputDir, "README.md"), renderMatcherIndex(descriptors))
}

func renderMatcherIndex(descriptors []sdk.MatcherDescriptor) string {
	var b strings.Builder
	b.WriteString("# Matcher Guides\n\n")
	b.WriteString("These generated pages explain Bomly's built-in enrichment matchers.\n\n")
	for _, descriptor := range descriptors {
		fmt.Fprintf(&b, "- [%s](%s.md)\n", humanMatcherTitle(descriptor.Name), descriptor.Name)
	}
	return b.String()
}

func renderMatcherMarkdown(descriptor sdk.MatcherDescriptor) string {
	behavior := matcherBehavior(descriptor.Name)
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", humanMatcherTitle(descriptor.Name))
	b.WriteString("<!-- Auto-generated by make generate. Do not edit manually. -->\n\n")
	fmt.Fprintf(&b, "%s\n\n", behavior.Summary)
	b.WriteString("| Property | Value |\n")
	b.WriteString("| --- | --- |\n")
	fmt.Fprintf(&b, "| Matcher name | `%s` |\n", descriptor.Name)
	fmt.Fprintf(&b, "| Runs by default | %s |\n", yesNo(descriptor.Enabled && !behavior.RequiresEnrich))
	fmt.Fprintf(&b, "| Requires enrichment | %s |\n", yesNo(behavior.RequiresEnrich))
	fmt.Fprintf(&b, "| Uses network | %s |\n", yesNo(behavior.UsesNetwork))
	fmt.Fprintf(&b, "| Cache behavior | %s |\n", behavior.Cache)
	fmt.Fprintf(&b, "| Output fields | %s |\n", strings.Join(behavior.OutputFields, ", "))
	if len(descriptor.Capabilities) > 0 {
		fmt.Fprintf(&b, "| Capabilities | %s |\n", codeList(descriptor.Capabilities))
	}
	if len(descriptor.SupportedEcosystems) > 0 {
		fmt.Fprintf(&b, "| Ecosystems | %s |\n", ecosystemCodeList(descriptor.SupportedEcosystems))
	}
	b.WriteString("\n## User Notes\n\n")
	b.WriteString(behavior.Notes)
	b.WriteString("\n")
	return b.String()
}

type matcherDocBehavior struct {
	Summary        string
	RequiresEnrich bool
	UsesNetwork    bool
	Cache          string
	OutputFields   []string
	Notes          string
}

func matcherBehavior(name string) matcherDocBehavior {
	switch name {
	case "osv":
		return matcherDocBehavior{
			Summary:        "Looks up package vulnerabilities in OSV and annotates matching packages.",
			RequiresEnrich: true,
			UsesNetwork:    true,
			Cache:          "Uses Bomly's matcher cache; cache failures are warnings, not scan failures.",
			OutputFields:   []string{"vulnerability ID", "severity", "aliases", "CVSS", "fixed version", "references", "KEV signal"},
			Notes:          "Run with `--enrich` to query OSV. Combine `--enrich --audit` when you want OSV data evaluated by policy in the same run.",
		}
	case "grype":
		return matcherDocBehavior{
			Summary:        "Uses Grype vulnerability matching against the resolved dependency graph.",
			RequiresEnrich: true,
			UsesNetwork:    false,
			Cache:          "Relies on Grype's local vulnerability database behavior.",
			OutputFields:   []string{"vulnerability ID", "severity", "CVSS", "fixed version", "references"},
			Notes:          "The full Bomly binary links Grype support. The lite binary uses an external `grype` executable on `PATH`.",
		}
	case "depsdev-license-checker":
		return matcherDocBehavior{
			Summary:        "Fetches package metadata from deps.dev to improve license coverage.",
			RequiresEnrich: true,
			UsesNetwork:    true,
			Cache:          "Uses Bomly's matcher cache; cache failures are non-fatal.",
			OutputFields:   []string{"license value", "license source", "matched package flag"},
			Notes:          "Run with `--enrich` when you want license metadata from deps.dev.",
		}
	case "clearlydefined-license-checker":
		return matcherDocBehavior{
			Summary:        "Fetches license metadata from ClearlyDefined.",
			RequiresEnrich: true,
			UsesNetwork:    true,
			Cache:          "Uses Bomly's matcher cache; cache failures are non-fatal.",
			OutputFields:   []string{"license value", "license source", "matched package flag"},
			Notes:          "Run with `--enrich` when you want ClearlyDefined license evidence.",
		}
	case "eol":
		return matcherDocBehavior{
			Summary:        "Checks endoflife.date for lifecycle metadata where Bomly can map a package or platform.",
			RequiresEnrich: true,
			UsesNetwork:    true,
			Cache:          "Uses Bomly's matcher cache; cache failures are non-fatal.",
			OutputFields:   []string{"metadata.eol", "matched package flag"},
			Notes:          "Run with `--enrich` to attach lifecycle metadata. Audit behavior depends on auditor policy support for that metadata.",
		}
	default:
		return matcherDocBehavior{
			Summary:        "Enriches Bomly package data.",
			RequiresEnrich: true,
			UsesNetwork:    false,
			Cache:          "Matcher-specific.",
			OutputFields:   []string{"matcher-specific package metadata"},
			Notes:          "Run with `--enrich` when this matcher should participate in scans.",
		}
	}
}

func chainSupportsInstallFirst(detectors []string) bool {
	for _, detectorName := range detectors {
		if detectorSupportsInstallFirst(detectorName) {
			return true
		}
	}
	return false
}

func detectorSupportsInstallFirst(detectorName string) bool {
	reg := registry.NewRegistry(registry.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	for _, descriptor := range reg.DetectorDescriptors() {
		if descriptor.Name == detectorName {
			return descriptor.SupportsInstallFirst
		}
	}
	return false
}

func commandHintsForChain(detectors []string) string {
	seen := make(map[string]struct{})
	values := make([]string, 0)
	for _, detector := range detectors {
		for _, command := range commandHintsForDetector(detector) {
			if _, ok := seen[command]; ok {
				continue
			}
			seen[command] = struct{}{}
			values = append(values, command)
		}
	}
	if len(values) == 0 {
		return "-"
	}
	return codeList(values)
}

func commandHintsForDetector(detector string) []string {
	switch {
	case strings.Contains(detector, "npm"):
		return []string{"npm"}
	case strings.Contains(detector, "pnpm"):
		return []string{"pnpm"}
	case strings.Contains(detector, "yarn"):
		return []string{"yarn"}
	case detector == "go-detector" || strings.Contains(detector, "gomod"):
		return []string{"go"}
	case strings.Contains(detector, "maven"):
		return []string{"mvn"}
	case strings.Contains(detector, "gradle"):
		return []string{"gradle"}
	case strings.Contains(detector, "composer"):
		return []string{"composer"}
	case strings.Contains(detector, "bundler") || strings.Contains(detector, "ruby"):
		return []string{"bundle"}
	case strings.Contains(detector, "pipenv"):
		return []string{"pipenv"}
	case strings.Contains(detector, "poetry"):
		return []string{"poetry"}
	case strings.Contains(detector, "uv"):
		return []string{"uv"}
	case strings.Contains(detector, "pip"):
		return []string{"pip"}
	case strings.Contains(detector, "cargo"):
		return []string{"cargo"}
	case strings.Contains(detector, "nuget"):
		return []string{"dotnet"}
	case strings.Contains(detector, "mix"):
		return []string{"mix"}
	case strings.Contains(detector, "conan"):
		return []string{"conan"}
	case strings.Contains(detector, "pub"):
		return []string{"dart"}
	case strings.Contains(detector, "swiftpm"):
		return []string{"swift"}
	case strings.Contains(detector, "sbt"):
		return []string{"sbt"}
	case strings.Contains(detector, "syft"):
		return []string{"syft for bomly-lite"}
	default:
		return nil
	}
}

func ecosystemCodeList(values []sdk.Ecosystem) string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, string(value))
	}
	return codeList(items)
}

func humanMatcherTitle(name string) string {
	switch name {
	case "osv":
		return "OSV"
	case "grype":
		return "Grype"
	case "depsdev-license-checker":
		return "deps.dev License Checker"
	case "clearlydefined-license-checker":
		return "ClearlyDefined License Checker"
	case "eol":
		return "endoflife.date"
	default:
		return titleWords(strings.ReplaceAll(name, "-", " "))
	}
}

func titleWords(value string) string {
	parts := strings.Fields(strings.ReplaceAll(value, "-", " "))
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func yesNo(value bool) string {
	if value {
		return "Yes"
	}
	return "No"
}

func writeMarkdown(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
