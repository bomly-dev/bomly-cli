package sbom

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bomly-dev/bomly-cli/internal/nodes"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/licenseexpr"
	"github.com/bomly-dev/bomly-sdk"
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

	// Modules are emitted alongside dependencies: they are the scanned
	// project's own artifacts, and an SBOM that omitted them would describe
	// the dependencies of a project it never named. Manifests are structural
	// and stay out.
	graphNodes := make([]sdk.GraphNode, 0, componentCount)
	for _, module := range g.ModuleNodes() {
		graphNodes = append(graphNodes, module)
	}
	for _, dep := range g.DependencyNodes() {
		graphNodes = append(graphNodes, dep)
	}
	for _, node := range graphNodes {
		coords, ok := componentCoordinates(node)
		if !ok {
			continue
		}
		version := coords.Version
		if version == "" && nodes.IsProjectOwned(node) && opts.ProjectRoot != nil {
			// The project's own modules have no registry version; the
			// project version is theirs.
			version = strings.TrimSpace(opts.ProjectRoot.Version)
		}
		pkg := node
		component := Component{
			ID:             pkg.NodeID(),
			Name:           coords.EcosystemName(),
			Org:            componentOrg(node),
			Version:        version,
			PURL:           pkg.NodeID(),
			Ecosystem:      string(coords.Ecosystem),
			PackageManager: coords.PackageManager.Name(),
			Type:           string(coords.Type),
		}
		if dep, isDep := pkg.(*sdk.DependencyNode); isDep {
			component.Scope = string(dep.PrimaryScope())
			component.Copyright = dep.Copyright
			component.Licenses = componentLicenses(sdk.DetectionLicenses(dep))
			component.Digests = componentDigests(dep.Digests)
			// The project's own records never take an external origin. This
			// guard closes the one remaining path -- a plugin-supplied graph
			// asserting an origin directly -- and module nodes cannot reach
			// it at all now, since origins live on dependency nodes.
			if !nodes.IsProjectOwned(pkg) && len(dep.Origins) > 0 {
				applyOrigin(&component, dep.Origins[0].Normalized())
			}
		}
		enrichComponentFromRegistry(&component, opts.Registry, pkg.NodeID(), nodes.IsProjectOwned(pkg))
		components = append(components, component)
		depsByRef[pkg.NodeID()] = nil
	}

	sort.Slice(components, func(i, j int) bool {
		return components[i].ID < components[j].ID
	})

	// Only depends-on edges become a document's dependency list: a
	// manifest-to-module edge is structural, and emitting it would assert a
	// relationship no detector made.
	g.WalkTypedEdges(func(from, to sdk.GraphNode, kind sdk.EdgeKind) bool {
		if kind != sdk.EdgeKindDependsOn {
			return true
		}
		if _, ok := depsByRef[from.NodeID()]; !ok {
			return true
		}
		depsByRef[from.NodeID()] = append(depsByRef[from.NodeID()], to.NodeID())
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
		rootIDs = append(rootIDs, r.NodeID())
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

	// When the graph has no single root (multiple manifests, multiple
	// ecosystems) the primary component would otherwise be an arbitrary
	// manifest node. Synthesize a pseudo root that represents the scanned
	// project and depends on every graph root so both formats agree on the
	// document's primary identity and the export forms one connected graph.
	if opts.ProjectRoot != nil && strings.TrimSpace(opts.ProjectRoot.Name) != "" && opts.RootComponentID == "" && len(rootIDs) != 1 {
		root := projectRootComponent(*opts.ProjectRoot)
		sort.Strings(rootIDs)
		components = append(components, root)
		sort.Slice(components, func(i, j int) bool {
			return components[i].ID < components[j].ID
		})
		dependencies = append(dependencies, Dependency{Ref: root.ID, DependsOn: rootIDs})
		sort.Slice(dependencies, func(i, j int) bool {
			return dependencies[i].Ref < dependencies[j].Ref
		})
		rootIDs = []string{root.ID}
	}

	serialNumber := strings.TrimSpace(opts.SerialNumber)
	nonce := ""
	if serialNumber == "" {
		nonce = newUUIDv4()
		serialNumber = "urn:uuid:" + nonce
	}
	documentNS := opts.DocumentNS
	if documentNS == "" {
		if nonce == "" {
			nonce = newUUIDv4()
		}
		documentNS = "https://bomly.dev/spdx/" + nonce
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
		ToolVersion:  strings.TrimSpace(opts.ToolVersion),
		Created:      created,
		SerialNumber: serialNumber,
		Provenance:   opts.Provenance,
		Lifecycle:    strings.TrimSpace(opts.Lifecycle),
		Aggregate:    strings.TrimSpace(opts.Aggregate),
		Components:   components,
		Dependencies: dependencies,
		Roots:        rootIDs,
	}, nil
}

// projectRootComponent synthesizes the pseudo component representing the
// scanned project. It carries a pkg:generic PURL so downstream consumers have
// a stable identifier for the primary component across updates.
func projectRootComponent(spec ProjectRoot) Component {
	name := strings.TrimSpace(spec.Name)
	version := strings.TrimSpace(spec.Version)
	purl := "pkg:generic/" + url.PathEscape(strings.ToLower(name))
	if version != "" {
		purl += "@" + url.PathEscape(version)
	}
	return Component{
		ID:      projectRootIDPrefix + sanitizeSPDXID(name),
		Name:    name,
		Version: version,
		Type:    "application",
		PURL:    purl,
	}
}

// newUUIDv4 returns a random RFC 4122 version-4 UUID string.
func newUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand never fails on supported platforms; fall back to a
		// time-derived nonce rather than emitting an empty identifier.
		return fmt.Sprintf("00000000-0000-4000-8000-%012x", time.Now().UnixNano()&0xffffffffffff)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// componentDigests projects detection-time dependency digests into the SBOM
// component model, normalizing values to lowercase hex so encoders can emit
// them as schema-valid CycloneDX hashes / SPDX checksums. Digests whose value
// cannot be normalized for a known algorithm are kept verbatim; encoders drop
// entries with unsupported algorithms.
func componentDigests(digests []sdk.Digest) []Digest {
	if len(digests) == 0 {
		return nil
	}
	out := make([]Digest, 0, len(digests))
	for _, d := range digests {
		value := strings.TrimSpace(d.Value)
		if value == "" {
			continue
		}
		out = append(out, Digest{Algorithm: string(d.Algorithm), Value: normalizeDigestValue(string(d.Algorithm), value)})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// digestHexSizes maps digest algorithms onto their raw byte lengths, used to
// validate base64-encoded values (npm SRI integrity) before hex re-encoding.
var digestHexSizes = map[string]int{
	"md5":      16,
	"sha1":     20,
	"sha-1":    20,
	"sha224":   28,
	"sha-224":  28,
	"sha256":   32,
	"sha-256":  32,
	"sha384":   48,
	"sha-384":  48,
	"sha512":   64,
	"sha-512":  64,
	"sha3-256": 32,
	"sha3-384": 48,
	"sha3-512": 64,
}

func normalizeDigestValue(algorithm, value string) string {
	size, ok := digestHexSizes[strings.ToLower(strings.TrimSpace(algorithm))]
	if !ok {
		return value
	}
	if len(value) == size*2 {
		if _, err := hex.DecodeString(value); err == nil {
			return strings.ToLower(value)
		}
	}
	// npm-style SRI integrity values are standard base64 of the raw digest.
	if raw, err := base64.StdEncoding.DecodeString(value); err == nil && len(raw) == size {
		return hex.EncodeToString(raw)
	}
	return value
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
// scorecardRepositoryURL renders a scorecard repository, which is a canonical
// host/owner/name identifier with no scheme, as a URL. It is held to the same
// invariant as detector-asserted origins.
func scorecardRepositoryURL(scorecard *sdk.PackageScorecard) (string, bool) {
	if scorecard == nil {
		return "", false
	}
	repository := strings.TrimSpace(scorecard.Repository)
	if repository == "" {
		return "", false
	}
	if !strings.Contains(repository, "://") {
		repository = "https://" + repository
	}
	return sdk.NormalizeOriginURL(repository, true)
}

// applyOrigin projects the origin a detector asserted onto a component. The
// value arrives already validated -- Normalized applies the SDK's rule and
// returns nothing when a location does not survive it -- so there is nothing to
// decide here: export publishes what detection resolved, or nothing.
func applyOrigin(component *Component, origin *sdk.DependencyOrigin) {
	if origin == nil {
		return
	}
	component.ArtifactURL = origin.ArtifactURL
	component.VCSURL = origin.Repository
	component.VCSRevision = origin.Revision
}

func enrichComponentFromRegistry(component *Component, registry *sdk.PackageRegistry, purl string, projectOwned bool) {
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
	if digests := componentDigests(pkg.Digests); len(digests) > 0 {
		component.Digests = digests
	}
	if len(pkg.Vulnerabilities) > 0 {
		component.Vulnerabilities = vulnerabilitiesFromPackage(pkg.EcosystemName(), pkg.Vulnerabilities)
	}
	if repository, ok := scorecardRepositoryURL(pkg.Scorecard); ok && component.VCSURL == "" && !projectOwned {
		// The registry package is shared by every occurrence of a PURL, but
		// a scorecard repository resolved for the consumed package must not
		// be attributed to the project's own record -- a local workspace or
		// fork that merely shares the identity.
		// The scorecard matcher resolved a canonical source repository for
		// this package. A detector-asserted repository is the stronger claim
		// (it came from the lockfile), so this only fills a gap.
		component.VCSURL = repository
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
func vulnerabilitiesFromPackage(packageName string, vulns []sdk.Vulnerability) []Vulnerability {
	out := make([]Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		vuln := Vulnerability{
			ID:             v.ID,
			Source:         v.Source,
			Severity:       string(v.ParsedSeverity),
			FixedVersions:  append([]string(nil), v.FixedVersions...),
			Description:    v.Details,
			Recommendation: vulnerabilityRecommendation(packageName, v.FixedVersions),
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

// vulnerabilityRecommendation renders remediation guidance from known fixed
// versions. Returns "" when no fix is known so consumers never see fabricated
// advice.
func vulnerabilityRecommendation(packageName string, fixedVersions []string) string {
	versions := make([]string, 0, len(fixedVersions))
	for _, v := range fixedVersions {
		if v = strings.TrimSpace(v); v != "" {
			versions = append(versions, v)
		}
	}
	if len(versions) == 0 {
		return ""
	}
	subject := strings.TrimSpace(packageName)
	if subject == "" {
		subject = "the affected package"
	}
	return "Upgrade " + subject + " to " + strings.Join(versions, " or ")
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
			Value:          normalizeSPDXLicenseExpression(license.Value),
			SPDXExpression: normalizeSPDXLicenseExpression(license.SPDXExpression),
			Type:           string(license.Type),
		})
	}
	return out
}

// deprecatedSPDXLicenseIDs maps SPDX license identifiers that the SPDX license
// list has deprecated onto their current replacements. Only unambiguous
// renames are listed; anything else passes through untouched.
var deprecatedSPDXLicenseIDs = map[string]string{
	"AGPL-1.0":                         "AGPL-1.0-only",
	"AGPL-3.0":                         "AGPL-3.0-only",
	"GFDL-1.1":                         "GFDL-1.1-only",
	"GFDL-1.2":                         "GFDL-1.2-only",
	"GFDL-1.3":                         "GFDL-1.3-only",
	"GPL-1.0":                          "GPL-1.0-only",
	"GPL-1.0+":                         "GPL-1.0-or-later",
	"GPL-2.0":                          "GPL-2.0-only",
	"GPL-2.0+":                         "GPL-2.0-or-later",
	"GPL-3.0":                          "GPL-3.0-only",
	"GPL-3.0+":                         "GPL-3.0-or-later",
	"LGPL-2.0":                         "LGPL-2.0-only",
	"LGPL-2.0+":                        "LGPL-2.0-or-later",
	"LGPL-2.1":                         "LGPL-2.1-only",
	"LGPL-2.1+":                        "LGPL-2.1-or-later",
	"LGPL-3.0":                         "LGPL-3.0-only",
	"LGPL-3.0+":                        "LGPL-3.0-or-later",
	"GPL-2.0-with-classpath-exception": "GPL-2.0-only WITH Classpath-exception-2.0",
}

// normalizeSPDXLicenseExpression replaces deprecated SPDX identifiers inside a
// license expression with their current names, preserving expression
// structure. Non-SPDX free-text values pass through unchanged.
func normalizeSPDXLicenseExpression(expression string) string {
	if strings.TrimSpace(expression) == "" {
		return expression
	}
	var b strings.Builder
	b.Grow(len(expression))
	token := strings.Builder{}
	flush := func() {
		if token.Len() == 0 {
			return
		}
		t := token.String()
		if replacement, ok := deprecatedSPDXLicenseIDs[t]; ok {
			b.WriteString(replacement)
		} else {
			b.WriteString(t)
		}
		token.Reset()
	}
	for _, r := range expression {
		if r == ' ' || r == '(' || r == ')' {
			flush()
			b.WriteRune(r)
			continue
		}
		token.WriteRune(r)
	}
	flush()
	return b.String()
}

// componentOrg returns the namespace to publish as the component's group.
//
// The PURL's namespace is preferred over the raw coordinate because it is the
// value the document already carries: PURL construction derives a namespace
// for Go modules whose coordinates leave Org empty, and it spells npm scopes
// with their leading "@". Reading it back keeps `group` and the PURL agreeing.
func componentOrg(node sdk.GraphNode) string {
	coords, ok := nodes.Coordinates(node)
	if !ok {
		return ""
	}
	if parsed := parsePURL(node.NodeID()); parsed != nil {
		if namespace := strings.TrimSpace(parsed.Namespace); namespace != "" {
			return namespace
		}
	}
	return strings.TrimSpace(coords.Org)
}

// licenseExpressionValue returns the license string a component carries: the
// SPDX expression when one was captured, otherwise the raw value. Both codecs
// read licenses through this so CycloneDX and SPDX never disagree about which
// string a license is.
func licenseExpressionValue(license License) string {
	if expression := strings.TrimSpace(license.SPDXExpression); expression != "" {
		return expression
	}
	return strings.TrimSpace(license.Value)
}

// componentLicenseValues returns the non-empty license strings a component
// carries, in order.
func componentLicenseValues(licenses []License) []string {
	values := make([]string, 0, len(licenses))
	for _, license := range licenses {
		if value := licenseExpressionValue(license); value != "" {
			values = append(values, value)
		}
	}
	return values
}

// allValidSPDXExpressions reports whether every value parses as an SPDX
// license expression. Registry sources record free text ("non-standard") in
// the same field as real expressions, so composing or publishing values as
// expressions requires checking them rather than trusting where they came from.
func allValidSPDXExpressions(values []string) bool {
	for _, value := range values {
		if !licenseexpr.Valid(value) {
			return false
		}
	}
	return true
}

// componentCoordinates returns the coordinates a node contributes to an SBOM
// component, and whether it contributes one at all. Manifests do not: they are
// structure, not artifacts.
func componentCoordinates(node sdk.GraphNode) (sdk.Coordinates, bool) {
	switch typed := node.(type) {
	case *sdk.DependencyNode:
		return typed.Coordinates, true
	case *sdk.ModuleNode:
		return typed.Coordinates, true
	default:
		return sdk.Coordinates{}, false
	}
}
