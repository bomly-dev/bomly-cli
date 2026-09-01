package sbom

import (
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-sdk"
)

// ToGraph converts a neutral SBOM document back into a dependency graph.
func ToGraph(doc *Document) (*sdk.Graph, error) {
	if doc == nil {
		return nil, ErrNilDocument
	}

	depsGraph := sdk.New()
	idMap := make(map[string]string, len(doc.Components))
	skipped := make(map[string]struct{})
	for _, component := range doc.Components {
		if isDocumentRootPseudoPackage(component) {
			skipped[component.ID] = struct{}{}
			continue
		}
		ecosystem := sdk.Ecosystem(strings.TrimSpace(component.Ecosystem))
		if ecosystem == sdk.EcosystemUnknown {
			if purl := parsePURL(component.PURL); purl != nil {
				ecosystem = ecosystemFromPURLType(purl.Type)
			}
		}
		packageManager := sdk.PackageManagerUnknown
		if manager, err := sdk.ParsePackageManager(component.PackageManager); err == nil {
			packageManager = manager
		}
		if packageManager == sdk.PackageManagerUnknown {
			packageManager = packageManagerForPURL(component.PURL, string(ecosystem), component.PackageManager)
		}
		// Identity is minted by the constructor (ADR-0041): a node's ID is
		// its canonical package URL, so the ingested component ID is not
		// carried in. A component whose coordinates cannot mint a well-formed
		// one is skipped rather than admitted under the document's own ID --
		// an SBOM component with no usable identity is not a dependency this
		// graph can say anything about.
		pkg, err := sdk.NewDependencyNode(sdk.Coordinates{
			Name:           component.Name,
			Version:        component.Version,
			Org:            ingestedCoordinateOrg(component),
			Ecosystem:      ecosystem,
			PackageManager: packageManager,
			Type:           sdk.ParsePackageType(component.Type),
			PURL:           strings.TrimSpace(component.PURL),
		})
		if err != nil {
			continue
		}
		pkg.Scopes = sdk.ScopesOf(sdk.Scope(component.Scope))
		pkg.Copyright = component.Copyright
		// The document's own component ID does not survive: the node answers
		// to the identity its coordinates mint, and idMap below is what
		// re-points the document's relationships onto it.
		packageID := pkg.NodeID()
		sdk.SetDetectionLicenses(pkg, graphLicenses(component.Licenses))

		if _, exists := depsGraph.Node(packageID); !exists {
			if err := depsGraph.AddNode(pkg); err != nil {
				return nil, fmt.Errorf("add package %q: %w", component.ID, err)
			}
		}
		idMap[component.ID] = packageID
	}

	for _, dependency := range doc.Dependencies {
		if _, ok := skipped[dependency.Ref]; ok {
			continue
		}
		fromID, ok := idMap[dependency.Ref]
		if !ok {
			// Dependency entries may reference the synthesized document root
			// (present only in CycloneDX metadata.component) or otherwise
			// dangling refs; neither has a graph node to anchor an edge.
			continue
		}
		for _, child := range dependency.DependsOn {
			if _, ok := skipped[child]; ok {
				continue
			}
			toID, ok := idMap[child]
			if !ok {
				continue
			}
			if fromID == toID {
				continue
			}
			if err := depsGraph.AddEdge(fromID, toID); err != nil {
				return nil, fmt.Errorf("add dependency %q -> %q: %w", fromID, toID, err)
			}
		}
	}

	return depsGraph, nil
}

func isDocumentRootPseudoPackage(component Component) bool {
	// Bomly's synthesized project root carries a pkg:generic PURL but is
	// still a stand-in for the scanned tree, not a resolved package.
	if IsProjectRootComponent(component) {
		return true
	}
	if strings.TrimSpace(component.PURL) != "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(component.Type), "file") && strings.TrimSpace(component.Version) == "" {
		return true
	}
	return false
}

// ingestedCoordinateOrg returns the namespace to carry on an ingested
// package's coordinates.
//
// SBOM producers split a namespaced package two ways. Bomly writes the whole
// ecosystem-native name ("@scope/pkg", "github.com/google/uuid") and repeats
// the namespace in `group`; most others write a bare name plus the namespace
// in `group`. Coordinates joins Org with Name to rebuild the display name, so
// which split arrived decides whether Org may be set at all: setting it on an
// already-qualified name yields "@scope/@scope/pkg", and leaving it unset on a
// bare name loses the namespace entirely.
//
// The name itself is never rewritten. Detectors and export both treat it as
// the ecosystem-native identity, so this only fills in the namespace when the
// name does not already carry it.
func ingestedCoordinateOrg(component Component) string {
	namespace := strings.TrimSpace(component.Org)
	if purl := parsePURL(component.PURL); purl != nil {
		if fromPURL := strings.TrimSpace(purl.Namespace); fromPURL != "" {
			// The PURL is the stronger claim: it is structured, and export
			// derives `group` from it in the first place.
			namespace = fromPURL
		}
	}
	if namespace == "" {
		return ""
	}

	// Compared case-insensitively: PURL normalization lowercases the namespace
	// for some types, so a Go module's namespace arrives as
	// "github.com/burntsushi" while its name keeps "github.com/BurntSushi/toml".
	// A case-sensitive test would miss that and double the namespace.
	name := strings.TrimSpace(component.Name)
	lowerName := strings.ToLower(name)
	lowerNamespace := strings.ToLower(namespace)
	if lowerName == lowerNamespace {
		return ""
	}
	// "/" separates npm scopes and Go module paths; ":" separates Maven
	// coordinates. A name already starting with the namespace and a separator
	// carries it, so Org must stay empty to avoid doubling it.
	for _, separator := range []string{"/", ":"} {
		if strings.HasPrefix(lowerName, lowerNamespace+separator) {
			return ""
		}
	}
	return namespace
}

func graphLicenses(licenses []License) []sdk.PackageLicense {
	if len(licenses) == 0 {
		return nil
	}
	out := make([]sdk.PackageLicense, 0, len(licenses))
	for _, license := range licenses {
		out = append(out, sdk.PackageLicense{
			Value:          license.Value,
			SPDXExpression: license.SPDXExpression,
			Type:           sdk.LicenseType(license.Type),
		})
	}
	return out
}
