package sbom

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/sdk"
)

var ErrNilGraph = errors.New("dependency graph is nil")

// FromDepGraph builds a neutral SBOM document from a dependency DAG.
func FromDepGraph(g *sdk.Graph, opts BuildOptions) (*Document, error) {
	if g == nil {
		return nil, ErrNilGraph
	}

	componentCount := g.Size()
	components := make([]Component, 0, componentCount)
	depsByRef := make(map[string][]string, componentCount)

	g.WalkNodes(func(pkg *sdk.Dependency) bool {
		component := Component{
			ID:             pkg.ID,
			Name:           pkg.QualifiedName(),
			Version:        pkg.Version,
			Scope:          string(pkg.PrimaryScope()),
			PURL:           pkg.PURL,
			Ecosystem:      string(pkg.Ecosystem),
			PackageManager: pkg.PackageManager.Name(),
			Type:           string(pkg.Type),
			Copyright:      pkg.Copyright,
			Licenses:       componentLicenses(sdk.DetectionLicenses(pkg)),
		}
		enrichComponentFromRegistry(&component, opts.Registry, pkg.PURL)
		components = append(components, component)
		depsByRef[pkg.ID] = nil
		return true
	})

	sort.Slice(components, func(i, j int) bool {
		return components[i].ID < components[j].ID
	})

	g.WalkEdges(func(from, to *sdk.Dependency) bool {
		depsByRef[from.ID] = append(depsByRef[from.ID], to.ID)
		return true
	})

	dependencies := make([]Dependency, 0, len(components))
	for _, c := range components {
		deps := depsByRef[c.ID]
		if len(deps) > 1 {
			sort.Strings(deps)
		}
		dependencies = append(dependencies, Dependency{
			Ref:       c.ID,
			DependsOn: deps,
		})
	}

	roots := g.Roots()
	rootIDs := make([]string, 0, len(roots))
	for _, r := range roots {
		rootIDs = append(rootIDs, r.ID)
	}
	if opts.RootComponentID != "" {
		for _, c := range components {
			if c.ID == opts.RootComponentID {
				rootIDs = []string{opts.RootComponentID}
				break
			}
		}
	}

	created := opts.Created.UTC()
	if created.IsZero() {
		created = time.Now().UTC()
	}

	documentName := opts.DocumentName
	if documentName == "" {
		documentName = defaultDocumentName
	}
	documentNS := opts.DocumentNS
	if documentNS == "" {
		documentNS = fmt.Sprintf("https://bomly.dev/spdx/%d", created.UnixNano())
	}
	toolName := opts.ToolName
	if toolName == "" {
		toolName = defaultToolName
	}
	toolNames := uniqueToolNames(append([]string{toolName}, opts.ToolNames...))

	return &Document{
		Name:         documentName,
		Namespace:    documentNS,
		Tool:         toolName,
		Tools:        toolNames,
		Created:      created,
		SerialNumber: opts.SerialNumber,
		Components:   components,
		Dependencies: dependencies,
		Roots:        rootIDs,
	}, nil
}

func uniqueToolNames(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// enrichComponentFromRegistry folds matching-stage data resolved by PURL onto a
// component: registry-learned licenses (preferred over detection-time when
// present), CPEs, digests, vulnerabilities, and EOL. registry may be nil.
func enrichComponentFromRegistry(component *Component, registry *sdk.PackageRegistry, purl string) {
	if component == nil || registry == nil || purl == "" {
		return
	}
	pkg, ok := registry.Get(purl)
	if !ok || pkg == nil {
		return
	}
	if len(pkg.Licenses) > 0 {
		component.Licenses = componentLicenses(pkg.Licenses)
	}
	if len(pkg.CPEs) > 0 {
		component.CPEs = append([]string(nil), pkg.CPEs...)
	}
	if len(pkg.Digests) > 0 {
		digests := make([]Digest, 0, len(pkg.Digests))
		for _, d := range pkg.Digests {
			if d.Value == "" {
				continue
			}
			digests = append(digests, Digest{Algorithm: string(d.Algorithm), Value: d.Value})
		}
		component.Digests = digests
	}
	if len(pkg.Vulnerabilities) > 0 {
		component.Vulnerabilities = vulnerabilitiesFromPackage(pkg.Vulnerabilities)
	}
	if pkg.EOL != nil {
		component.EOL = &EOL{
			EOL:           pkg.EOL.EOL,
			EOLDate:       pkg.EOL.EOLDate,
			Cycle:         pkg.EOL.Cycle,
			LatestVersion: pkg.EOL.LatestVersion,
		}
	}
}

// vulnerabilitiesFromPackage projects matching-stage advisories into the
// format-agnostic SBOM vulnerability model. Severity/score/vector come from the
// first CVSS entry when present, falling back to the parsed severity band.
func vulnerabilitiesFromPackage(vulns []sdk.Vulnerability) []Vulnerability {
	out := make([]Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		vuln := Vulnerability{
			ID:            v.ID,
			Source:        v.Source,
			Severity:      string(v.ParsedSeverity),
			FixedVersions: append([]string(nil), v.FixedVersions...),
			Description:   v.Details,
		}
		if vuln.Source == "" {
			vuln.Source = v.DataSource
		}
		if len(v.CVSS) > 0 {
			vuln.Score = new(v.CVSS[0].Score)
			vuln.Vector = v.CVSS[0].Vector
			vuln.Method = cvssMethodForVersion(string(v.CVSS[0].Version))
		}
		for _, cwe := range v.CWEs {
			if id := cweNumber(cwe.ID); id > 0 {
				vuln.CWEs = append(vuln.CWEs, id)
			}
		}
		for _, ref := range v.References {
			if url := strings.TrimSpace(ref.URL); url != "" {
				vuln.Advisories = append(vuln.Advisories, url)
			}
		}
		out = append(out, vuln)
	}
	return out
}

// cweNumber extracts the integer portion of a CWE identifier such as
// "CWE-79" → 79. Returns 0 when no number is present.
func cweNumber(id string) int {
	id = strings.TrimSpace(id)
	if id == "" {
		return 0
	}
	digits := strings.TrimLeftFunc(id, func(r rune) bool { return r < '0' || r > '9' })
	digits = strings.TrimRightFunc(digits, func(r rune) bool { return r < '0' || r > '9' })
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0
	}
	return n
}

// cvssMethodForVersion maps a CVSS version string to a CycloneDX scoring method
// label (e.g. "3.1" → "CVSSv31"). Returns "other" when unrecognized.
func cvssMethodForVersion(version string) string {
	switch strings.TrimSpace(version) {
	case "2", "2.0":
		return "CVSSv2"
	case "3", "3.0":
		return "CVSSv3"
	case "3.1":
		return "CVSSv31"
	case "4", "4.0":
		return "CVSSv4"
	default:
		return "other"
	}
}

func componentLicenses(licenses []sdk.PackageLicense) []License {
	if len(licenses) == 0 {
		return nil
	}
	out := make([]License, 0, len(licenses))
	for _, license := range licenses {
		out = append(out, License{
			Value:          license.Value,
			SPDXExpression: license.SPDXExpression,
			Type:           string(license.Type),
		})
	}
	return out
}
