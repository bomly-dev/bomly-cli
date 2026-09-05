package sbom

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/graphview"
	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/spdxkit"
)

var ErrNilGraph = errors.New("dependency graph is nil")

// FromDepGraph builds a neutral SBOM document from a dependency DAG.
//
// For a graph that came from ingested SBOMs, prefer FromGraphEntries: this
// entry point has no way to see what those documents said about themselves,
// and so exports a document that credits only Bomly.
func FromDepGraph(g *sdk.Graph, opts BuildOptions) (*Document, error) {
	return FromGraphEntries(g, nil, opts)
}

// FromGraphEntries builds a neutral SBOM document from the prepared graph
// entries and the consolidated graph they produced.
//
// Both are passed, and neither is derived from the other. The graph is the
// one already selected for output -- consolidation renamed its identities and
// the scope filter decided what stays -- so re-merging the entries here would
// export a different graph than the rest of the command reports. The entries
// are here for the one thing only they carry: what each source document
// asserted about itself, which the merge into a single graph necessarily
// discards (ADR-0037).
func FromGraphEntries(g *sdk.Graph, entries []sdk.GraphEntry, opts BuildOptions) (*Document, error) {
	if g == nil {
		return nil, ErrNilGraph
	}
	sources := make([]sdk.DocumentAssertions, 0, len(entries))
	for _, entry := range entries {
		if entry.Document == nil {
			continue
		}
		sources = append(sources, *entry.Document)
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
		if version == "" && sdk.IsProjectOwned(node) && opts.ProjectRoot != nil {
			// The project's own modules have no registry version; the
			// project version is theirs.
			version = strings.TrimSpace(opts.ProjectRoot.Version)
		}
		pkg := node
		component := Component{
			ID: pkg.NodeID(),
			// The bom-ref is the node ID; the purl is not. A module's ID is
			// its declaring path, and publishing that in a field both formats
			// define as a Package URL hands every consumer a value it cannot
			// parse -- so a module publishes the package URL its coordinates
			// mint, and only that.
			Name:           coords.EcosystemName(),
			Org:            componentOrg(node),
			Version:        version,
			PURL:           componentPURL(node),
			Ecosystem:      string(coords.Ecosystem),
			PackageManager: coords.PackageManager.Name(),
			Type:           string(coords.Type),
		}
		if dep, isDep := pkg.(*sdk.DependencyNode); isDep {
			component.Scope = string(dep.PrimaryScope())
			component.Copyright = dep.Copyright
			component.Licenses = componentLicenses(sdk.DetectionLicenses(dep))
			component.Digests = componentDigests(dep.Digests)
			applyNodeAssertions(&component, dep)
			// The project's own records never take an external origin. This
			// guard closes the one remaining path -- a plugin-supplied graph
			// asserting an origin directly -- and module nodes cannot reach
			// it at all now, since origins live on dependency nodes.
			if !sdk.IsProjectOwned(pkg) && len(dep.Origins) > 0 {
				applyOrigins(&component, dep.Origins)
			}
		}
		enrichComponentFromRegistry(&component, opts.Registry, pkg.NodeID(), sdk.IsProjectOwned(pkg))
		components = append(components, component)
		depsByRef[pkg.NodeID()] = nil
	}

	sort.Slice(components, func(i, j int) bool {
		return components[i].ID < components[j].ID
	})

	componentIDs := make(map[string]struct{}, len(components))
	for _, c := range components {
		componentIDs[c.ID] = struct{}{}
	}

	// A component's dependencies are the components beneath it, with any
	// structural node in between stepped through rather than named.
	//
	// A workspace is module -> child manifest -> child module, and the two
	// edges are typed differently: the first derives depends-on and the
	// second describes. Publishing the first named the manifest, which is not
	// a component, so CycloneDX carried a dependsOn pointing at no bom-ref;
	// filtering the second dropped the hop entirely, so the child module's
	// whole subtree came loose. Contracting the path keeps the relationship
	// the graph asserts and names only components.
	//
	// Every entry is recomputed rather than merged onto what the edge walk
	// left, so a component whose only child was a structural dead end ends up
	// with no dependencies instead of keeping a dangling one. graphview owns
	// the walk, so this agrees with scan JSON by construction instead of by
	// memory -- the two disagreed for exactly one commit, which is how this
	// was found.
	for ref := range depsByRef {
		depsByRef[ref] = graphview.ChildrenAmong(g, ref, componentIDs)
	}

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

	// Only roots that became components. A manifest node is a root of the
	// graph but is deliberately not exported as a component, so copying its ID
	// here left the document naming a primary component that does not exist in
	// it -- and, being exactly one ID, it also suppressed the synthesized root
	// below that would have repaired it.
	rootIDs := exportedRootIDs(g, componentIDs)
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

	toolName := opts.ToolName
	if toolName == "" {
		toolName = defaultToolName
	}
	toolNames := uniqueToolNames(append([]string{toolName}, opts.ToolNames...))

	doc := &Document{
		Name:         opts.DocumentName,
		Namespace:    opts.DocumentNS,
		Tool:         toolName,
		Tools:        toolNames,
		ToolVersion:  strings.TrimSpace(opts.ToolVersion),
		Created:      created,
		SerialNumber: strings.TrimSpace(opts.SerialNumber),
		Provenance:   opts.Provenance,
		Lifecycle:    strings.TrimSpace(opts.Lifecycle),
		Aggregate:    strings.TrimSpace(opts.Aggregate),
		Components:   components,
		Dependencies: dependencies,
		Roots:        rootIDs,
	}

	// Before the identity is minted, not after: a conversion adopts its
	// single source's identity, and it can only do that while the slot is
	// still empty. An identity the caller pinned always wins over both.
	applySourceAssertions(doc, sources)
	mintDocumentIdentity(doc)
	if doc.Name == "" {
		doc.Name = defaultDocumentName
	}
	return doc, nil
}

// mintDocumentIdentity fills whichever identity slots are still empty with a
// freshly generated one, so a document always identifies itself.
//
// Both slots share a nonce when both are minted, which keeps an export's
// SPDX namespace and CycloneDX serial recognizably the same document.
func mintDocumentIdentity(doc *Document) {
	nonce := ""
	if doc.SerialNumber == "" {
		nonce = newUUIDv4()
		doc.SerialNumber = "urn:uuid:" + nonce
	}
	if doc.Namespace == "" {
		if nonce == "" {
			nonce = newUUIDv4()
		}
		doc.Namespace = "https://bomly.dev/spdx/" + nonce
	}
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
// exportedRootIDs names the graph roots the document actually contains.
//
// A manifest node is a root of the graph but never a component: it is
// structural, and a document naming it as its primary component points at
// something that is not there. Consolidation does produce exactly that shape
// -- several disconnected package roots attached beneath one synthesized
// manifest -- and naming the manifest also read as a single root, which
// suppressed the synthesized project root that would have repaired it.
//
// A structural root is replaced by the exported nodes beneath it rather than
// dropped, so the roots the document reports are the ones a reader means: the
// project's modules and top-level packages.
func exportedRootIDs(g *sdk.Graph, exported map[string]struct{}) []string {
	roots := g.Roots()
	ids := make([]string, 0, len(roots))
	seen := make(map[string]struct{}, len(roots))
	visited := make(map[string]struct{}, len(roots))

	var collect func(node sdk.GraphNode)
	collect = func(node sdk.GraphNode) {
		if sdk.IsNilNode(node) {
			return
		}
		id := node.NodeID()
		if _, done := visited[id]; done {
			return
		}
		visited[id] = struct{}{}
		if _, ok := exported[id]; ok {
			if _, duplicate := seen[id]; !duplicate {
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
			return
		}
		children, err := g.DirectDependencies(id)
		if err != nil {
			return
		}
		for _, child := range children {
			collect(child)
		}
	}
	for _, root := range roots {
		collect(root)
	}
	return ids
}

// applyOrigins records every place a package was resolved from.
//
// The first origin fills the single-valued fields the formats' own download
// and VCS slots need. The rest used to be dropped here, which meant a folded
// node carrying two registries -- the dependency-confusion signal ADR-0041
// keeps deliberately -- exported as though it had come from one. Each is
// re-normalized, so an origin that does not survive the publication gates is
// discarded rather than published.
func applyOrigins(component *Component, origins []sdk.DependencyOrigin) {
	if component == nil {
		return
	}
	seen := make(map[ComponentOrigin]struct{}, len(origins))
	for _, origin := range origins {
		normalized := origin.Normalized()
		if normalized == nil {
			continue
		}
		entry := ComponentOrigin{
			ArtifactURL: normalized.ArtifactURL,
			Repository:  normalized.Repository,
			Revision:    normalized.Revision,
		}
		if _, duplicate := seen[entry]; duplicate {
			continue
		}
		seen[entry] = struct{}{}
		component.Origins = append(component.Origins, entry)
	}
	if len(component.Origins) == 0 {
		return
	}
	primary := component.Origins[0]
	component.ArtifactURL = primary.ArtifactURL
	component.VCSURL = primary.Repository
	component.VCSRevision = primary.Revision
}

// applyNodeAssertions copies the claims a node carries about itself onto the
// component the document will hold (ADR-0037, issue #396).
//
// Every value re-clears its own gate on the way out, even though it cleared
// one on the way in. The node is not a trusted carrier: a detector or an
// external plugin can write these fields directly, and a value that entered
// through a plugin never passed an ingest gate at all. Gating only at the
// boundary that happens to be upstream is how #391's last unfixed finding
// worked -- references restored from metadata were published without
// re-clearing anything.
//
// A rejected value is dropped rather than repaired: the gates decide what is
// publishable, and a "fixed" contact or reference would be an assertion no
// source made.
func applyNodeAssertions(component *Component, dep *sdk.DependencyNode) {
	if component == nil || dep == nil {
		return
	}
	if dep.Supplier != nil {
		if contact, ok := dep.Supplier.Normalized(); ok {
			component.Supplier = &contact
		}
	}
	if dep.Originator != nil {
		if contact, ok := dep.Originator.Normalized(); ok {
			component.Originator = &contact
		}
	}
	component.Description = sdk.NormalizeDescription(dep.Description)
	component.Homepage = sdk.NormalizeHomepage(dep.Homepage)
	component.ExternalReferences = publishableReferences(dep.ExternalReferences)
	if len(dep.CPEs) > 0 && len(component.CPEs) == 0 {
		component.CPEs = append([]string(nil), dep.CPEs...)
	}
}

// publishableReferences returns the references that survive the SDK gate,
// deduplicated by the reference's own identity.
//
// MergeExternalReferences is the union rule, so calling it with no existing
// set both normalizes and dedupes -- the set merge class stated in ADR-0037,
// applied through the one implementation of it rather than a second sort-and-
// compare written here.
func publishableReferences(refs []sdk.ExternalReference) []sdk.ExternalReference {
	if len(refs) == 0 {
		return nil
	}
	return sdk.MergeExternalReferences(nil, refs)
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

// componentPURL returns the package URL a component publishes.
//
// A dependency node's identity is one already. A module node's is not: it is
// the module grammar, which carries the declaring manifest path so two
// members of one workspace cannot collide. The package URL its coordinates
// mint is what belongs in the document, and a module whose coordinates mint
// none publishes no purl rather than an unparseable one.
// This was the codec's own copy of the projection, kept separate because an
// SBOM codec importing the CLI's output layer would invert the layering. Both
// copies converge here: bomly-sdk v0.9.2 took the accessor
// (bomly-dev/bomly-sdk#43), which is where it belongs (ADR-0040), and the
// question every surface asks of a node now has exactly one answer.
func componentPURL(node sdk.GraphNode) string {
	return sdk.NodePURL(node)
}

// componentOrg returns the namespace to publish as the component's group.
//
// The PURL's namespace is preferred over the raw coordinate because it is the
// value the document already carries: PURL construction derives a namespace
// for Go modules whose coordinates leave Org empty, and it spells npm scopes
// with their leading "@". Reading it back keeps `group` and the PURL agreeing.
func componentOrg(node sdk.GraphNode) string {
	coords, ok := sdk.NodeCoordinates(node)
	if !ok {
		return ""
	}
	// componentPURL, not NodeID: a module's ID is the structural
	// "module:<path>#<purl>" grammar and parses as no package URL at all, so
	// reading it here dropped the group from every module component -- a Go
	// module root carries its whole path in Name with an empty Org, and
	// published "pkg:golang/github.com/bomly/example" with no group beside it.
	if parsed := parsePURL(componentPURL(node)); parsed != nil {
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
		if !spdxkit.Valid(value) {
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
