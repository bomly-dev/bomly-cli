package sbom

import (
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-sdk"
	spdxcommon "github.com/spdx/tools-golang/spdx/v2/common"
)

// applyIngestedAssertions carries a source document's own claims onto the
// node, so a conversion keeps what the document said (issue #396).
//
// Only coordinates, scope, copyright and licenses used to survive this hop,
// so `bomly scan --sbom --format spdx` silently returned a document asserting
// far less than its input. These are the fields ADR-0037 typed for exactly
// that reason.
//
// Every value clears its own gate here. An ingested document is untrusted
// input that Bomly re-emits under its own name: a supplier name carrying
// control characters would corrupt SPDX's line-oriented form, a reference
// locator can be a local path or carry credentials, and #391 leaked
// credentials twice through URL positions its author had not considered. The
// gates are the SDK's, so ingest cannot hold a value to a weaker standard
// than export does.
//
// What is deliberately not set here is Source. It feeds
// RegistryMatchEligible, and an ingested component must stay eligible for
// enrichment so `bomly scan --sbom --enrich` keeps working.
func applyIngestedAssertions(pkg *sdk.DependencyNode, component Component) {
	if pkg == nil {
		return
	}
	if component.Supplier != nil {
		if contact, ok := component.Supplier.Normalized(); ok {
			pkg.Supplier = &contact
		}
	}
	if component.Originator != nil {
		if contact, ok := component.Originator.Normalized(); ok {
			pkg.Originator = &contact
		}
	}
	pkg.Description = stableValue(sdk.NormalizeDescription, component.Description)
	pkg.Homepage = stableValue(sdk.NormalizeHomepage, component.Homepage)
	pkg.ExternalReferences = sdk.MergeExternalReferences(nil, component.ExternalReferences)
	pkg.Digests = ingestedDigests(component.Digests)
	pkg.CPEs = ingestedCPEs(component.CPEs)
}

// stableValue normalizes until the result stops changing, and drops a value
// that will not settle.
//
// A gate that is not idempotent breaks the round trip this whole change
// exists to provide: a description carrying invalid UTF-8 normalizes to three
// bytes per bad byte, which can push it past the length bound that was
// applied before the repair -- so the next pass sees an over-long value and
// returns empty. The field then survives one hop and vanishes on the next.
// Found by FuzzIngestedAssertions within a minute of first running, and filed
// as bomly-dev/bomly-sdk#54.
//
// This does not re-implement any rule: it applies the SDK's own function
// until it reaches its fixed point, which is a policy decision about how much
// to trust a gate rather than a second opinion about what the gate should
// say. Publishing a value that changes on the next hop is worse than
// publishing nothing, so a value that has not settled after one further pass
// is dropped. Remove this once #54 ships; the fuzz target asserts the
// property either way.
func stableValue(normalize func(string) string, value string) string {
	first := normalize(value)
	second := normalize(first)
	if first != second {
		return ""
	}
	return first
}

// ingestedDigests admits the checksums a document stated, each through the
// digest gate.
//
// A digest names an algorithm from a vocabulary both formats keep extending,
// and a value whose shape that algorithm fixes; a document may state neither
// correctly. Digest.Normalized is the gate, so the algorithm set stays the
// SDK's -- a length check written here would go stale in the direction of
// silently dropping a real hash, which is precisely how a transcribed digest
// table lost CycloneDX's Streebog entries once already.
func ingestedDigests(digests []Digest) []sdk.Digest {
	if len(digests) == 0 {
		return nil
	}
	admitted := make([]sdk.Digest, 0, len(digests))
	seen := make(map[sdk.Digest]struct{}, len(digests))
	for _, digest := range digests {
		normalized, ok := sdk.Digest{
			Algorithm: sdk.DigestAlgorithm(digest.Algorithm),
			Value:     digest.Value,
		}.Normalized()
		if !ok {
			continue
		}
		if _, duplicate := seen[normalized]; duplicate {
			continue
		}
		seen[normalized] = struct{}{}
		admitted = append(admitted, normalized)
	}
	if len(admitted) == 0 {
		return nil
	}
	return admitted
}

// ingestedCPEs admits the CPEs a document stated, dropping any that is not a
// well-formed binding. A malformed identifier published back out would be a
// claim about a platform no source made, and a CPE decides which advisories
// match -- a wrong one is a wrong vulnerability answer.
//
// The grammar is the SDK's. It is reachable only through the external-
// reference gate, so each value is offered as a reference under both CPE
// reference types and admitted if either accepts it: 2.2 and 2.3 are
// genuinely different bindings, and a value is whichever one it parses as.
// Writing the grammar here instead is the mistake #396 records being
// retrofitted once already -- the hand-rolled CPE validator its fuzz target
// immediately broke.
func ingestedCPEs(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cpeTypes := []string{spdxcommon.TypeSecurityCPE23Type, spdxcommon.TypeSecurityCPE22Type}
	admitted := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		for _, cpeType := range cpeTypes {
			reference, ok := sdk.ExternalReference{
				Category: sdk.ExternalReferenceCategorySecurity,
				Type:     cpeType,
				Locator:  value,
			}.Normalized()
			if !ok {
				continue
			}
			if _, duplicate := seen[reference.Locator]; duplicate {
				break
			}
			seen[reference.Locator] = struct{}{}
			admitted = append(admitted, reference.Locator)
			break
		}
	}
	if len(admitted) == 0 {
		return nil
	}
	return admitted
}

// componentIdentityHint describes a component in an error, preferring the
// package URL it stated because that is the field an author has to correct.
func componentIdentityHint(component Component) string {
	if purl := strings.TrimSpace(component.PURL); purl != "" {
		return "purl " + purl
	}
	name := strings.TrimSpace(component.Name)
	if name == "" {
		return "unnamed component"
	}
	if version := strings.TrimSpace(component.Version); version != "" {
		return "name " + name + "@" + version
	}
	return "name " + name
}

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
		// carried in.
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
			// Loudly, not silently. This used to `continue`, which dropped
			// the component and every relationship naming it -- so an SBOM
			// carrying one malformed package URL produced a smaller graph,
			// and a scan of it reported clean while a genuinely vulnerable
			// dependency was simply absent from the answer. Under-reporting
			// a vulnerability is the worst way for a security tool to fail,
			// and it is exactly what a corrupt document should not be able
			// to buy.
			//
			// Refusing the document is the same rule ADR-0041 applies at the
			// plugin wire: an identity that cannot mint a well-formed package
			// URL is an error, with no lenient path and no pkg:generic
			// coercion. The message names the component so the author can
			// find it, since the fix is in their document rather than here.
			return nil, fmt.Errorf("sbom component %q (%s): %w", component.ID, componentIdentityHint(component), err)
		}
		pkg.Scopes = append([]sdk.Scope(nil), component.Scopes...)
		pkg.Copyright = component.Copyright
		applyIngestedAssertions(pkg, component)
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
