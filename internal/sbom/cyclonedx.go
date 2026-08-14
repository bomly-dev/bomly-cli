package sbom

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type cycloneDXCodec struct {
	version Target
}

func (c cycloneDXCodec) encodeJSON(doc *Document, opts EncodeOptions) ([]byte, error) {
	bom := cdx.NewBOM()
	bom.SerialNumber = doc.SerialNumber

	components := make([]cdx.Component, 0, len(doc.Components))
	for _, comp := range doc.Components {
		if IsProjectRootComponent(comp) {
			// The synthesized project root lives in metadata.component (and
			// keeps its entry in the dependencies section); repeating it in
			// the component inventory would double-count it.
			continue
		}
		component := cdx.Component{
			BOMRef:     comp.ID,
			Type:       cycloneDXComponentType(comp.Type),
			Name:       comp.NameOrID(),
			Scope:      cycloneDXScope(comp.Scope),
			Version:    comp.Version,
			PackageURL: comp.PURL,
			Copyright:  comp.Copyright,
		}
		if licenses := cycloneDXLicenses(comp.Licenses); len(licenses) > 0 {
			component.Licenses = &licenses
		}
		if len(comp.CPEs) > 0 {
			component.CPE = comp.CPEs[0]
		}
		if hashes := cycloneDXHashes(comp.Digests); len(hashes) > 0 {
			component.Hashes = &hashes
		}
		if props := cycloneDXEOLProperties(comp.EOL); len(props) > 0 {
			component.Properties = &props
		}
		// Emit whenever any part of the entity survives, not only when it has
		// a name — the name is optional on a CycloneDX organizational entity.
		// A Person-typed supplier is still omitted: CycloneDX has no
		// person-valued supplier, so an SPDX "Person: Alice" would be recast
		// as an organization, changing a compliance-relevant assertion.
		hasSupplier := comp.Supplier != "" || len(comp.SupplierURLs) > 0 || len(comp.SupplierContacts) > 0
		if hasSupplier && !strings.EqualFold(comp.SupplierType, "Person") {
			supplier := &cdx.OrganizationalEntity{Name: comp.Supplier}
			if len(comp.SupplierURLs) > 0 {
				urls := append([]string(nil), comp.SupplierURLs...)
				supplier.URL = &urls
			}
			if len(comp.SupplierContacts) > 0 {
				contacts := make([]cdx.OrganizationalContact, 0, len(comp.SupplierContacts))
				for _, c := range comp.SupplierContacts {
					contacts = append(contacts, cdx.OrganizationalContact{
						Name: c.Name, Email: c.Email, Phone: c.Phone,
					})
				}
				supplier.Contact = &contacts
			}
			component.Supplier = supplier
		}
		component.Publisher = comp.Originator
		component.Description = firstNonEmpty(comp.Description, comp.Summary)
		if refs := cycloneDXComponentReferences(comp); len(refs) > 0 {
			component.ExternalReferences = &refs
		}
		components = append(components, component)
	}
	bom.Components = &components

	if vulns := cycloneDXVulnerabilities(doc.Components); len(vulns) > 0 {
		bom.Vulnerabilities = &vulns
	}

	deps := make([]cdx.Dependency, 0, len(doc.Dependencies))
	for _, dep := range doc.Dependencies {
		cd := cdx.Dependency{Ref: dep.Ref}
		if len(dep.DependsOn) > 0 {
			children := make([]string, len(dep.DependsOn))
			copy(children, dep.DependsOn)
			cd.Dependencies = &children
		}
		deps = append(deps, cd)
	}
	bom.Dependencies = &deps

	metadata := &cdx.Metadata{
		Timestamp: doc.CreatedOrNow().Format(time.RFC3339),
		Tools:     cycloneDXTools(doc.ToolNamesOrDefault(), doc.ToolOrDefault(), doc.ToolVersion),
	}
	if root := chooseRoot(doc); root != nil {
		metadata.Component = &cdx.Component{
			BOMRef:     root.ID,
			Type:       cycloneDXComponentType(firstNonEmpty(root.Type, "application")),
			Name:       root.NameOrID(),
			Scope:      cycloneDXScope(root.Scope),
			Version:    root.Version,
			PackageURL: root.PURL,
		}
		if refs := cycloneDXSecurityReferences(doc.Provenance); len(refs) > 0 {
			metadata.Component.ExternalReferences = &refs
		}
	}
	if doc.Provenance.Manufacturer != "" {
		metadata.Manufacturer = &cdx.OrganizationalEntity{Name: doc.Provenance.Manufacturer}
		author := cdx.OrganizationalContact{Name: doc.Provenance.Manufacturer}
		if email := bareEmail(doc.Provenance.SecurityContact); email != "" {
			author.Email = email
		}
		metadata.Authors = &[]cdx.OrganizationalContact{author}
	}
	if props := cycloneDXMetadataProperties(doc.Provenance); len(props) > 0 {
		metadata.Properties = &props
	}
	if phase := cycloneDXLifecyclePhase(doc.Lifecycle); phase != "" {
		metadata.Lifecycles = &[]cdx.Lifecycle{{Phase: phase}}
	}
	bom.Metadata = metadata

	if aggregate := cycloneDXAggregate(doc.Aggregate); aggregate != "" {
		bom.Compositions = &[]cdx.Composition{{Aggregate: aggregate}}
	}

	var out bytes.Buffer
	enc := cdx.NewBOMEncoder(&out, cdx.BOMFileFormatJSON).SetPretty(opts.Pretty)
	if err := enc.EncodeVersion(bom, toCycloneDXVersion(c.version)); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (c cycloneDXCodec) decodeJSON(data []byte) (*Document, error) {
	bom := new(cdx.BOM)
	dec := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON)
	if err := dec.Decode(bom); err != nil {
		return nil, err
	}

	componentByID := make(map[string]Component)
	if bom.Components != nil {
		for _, comp := range *bom.Components {
			componentByID[comp.BOMRef] = componentFromCycloneDX(comp)
		}
	}

	primaryRef := ""
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		primaryRef = bom.Metadata.Component.BOMRef
	}

	dependencies := make([]Dependency, 0, len(componentByID))
	inDegree := make(map[string]int, len(componentByID))
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			if _, known := componentByID[dep.Ref]; !known && (isProjectRootID(dep.Ref) || dep.Ref == primaryRef) {
				// The primary component lives only in metadata.component; its
				// dependency entry links the document root to the real graph
				// roots and must not demote those roots on re-ingestion.
				continue
			}
			ds := make([]string, 0)
			if dep.Dependencies != nil {
				ds = append(ds, *dep.Dependencies...)
				for _, child := range ds {
					inDegree[child]++
				}
			}
			if len(ds) > 1 {
				sort.Strings(ds)
			}
			dependencies = append(dependencies, Dependency{
				Ref:       dep.Ref,
				DependsOn: ds,
			})
		}
	}

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		root := bom.Metadata.Component
		switch existing, listed := componentByID[root.BOMRef]; {
		case listed:
			// A producer may describe the primary component in both places
			// and put assertions only on the metadata copy. Fold those in;
			// the inventory entry stays authoritative for anything it set.
			mergeComponentAssertions(&existing, componentFromCycloneDX(*root))
			componentByID[root.BOMRef] = existing
		case len(componentByID) == 0:
			componentByID[root.BOMRef] = componentFromCycloneDX(*root)
		}
		// A primary component that appears only in metadata.component while
		// an inventory exists is deliberately not promoted to a node: it is
		// the document's subject, re-synthesized on export, and adding it
		// here would demote the real graph roots on re-ingestion.
	}

	components := make([]Component, 0, len(componentByID))
	for _, comp := range componentByID {
		components = append(components, comp)
	}
	sort.Slice(components, func(i, j int) bool { return components[i].ID < components[j].ID })

	if len(dependencies) == 0 {
		dependencies = make([]Dependency, 0, len(components))
		for _, comp := range components {
			dependencies = append(dependencies, Dependency{Ref: comp.ID})
		}
	}
	sort.Slice(dependencies, func(i, j int) bool { return dependencies[i].Ref < dependencies[j].Ref })

	roots := make([]string, 0)
	for _, comp := range components {
		if inDegree[comp.ID] == 0 {
			roots = append(roots, comp.ID)
		}
	}
	sort.Strings(roots)

	created := time.Time{}
	if bom.Metadata != nil && bom.Metadata.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, bom.Metadata.Timestamp); err == nil {
			created = t.UTC()
		}
	}

	return &Document{
		Name:         defaultDocumentName,
		Tool:         cycloneDXPrimaryToolName(bom.Metadata),
		Tools:        cycloneDXToolNames(bom.Metadata),
		Created:      created,
		SerialNumber: bom.SerialNumber,
		Components:   components,
		Dependencies: dependencies,
		Roots:        roots,
	}, nil
}

func cycloneDXTools(names []string, primaryTool, toolVersion string) *cdx.ToolsChoice {
	if len(names) == 0 {
		return nil
	}
	components := make([]cdx.Component, 0, len(names))
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			continue
		}
		component := cdx.Component{
			Type: cdx.ComponentTypeApplication,
			Name: name,
		}
		if name == primaryTool {
			component.Version = toolVersion
		}
		components = append(components, component)
	}
	if len(components) == 0 {
		return nil
	}
	return &cdx.ToolsChoice{Components: &components}
}

// cycloneDXSecurityReferences maps provenance contact fields onto external
// references attached to the primary component.
func cycloneDXSecurityReferences(p Provenance) []cdx.ExternalReference {
	refs := make([]cdx.ExternalReference, 0, 2)
	if contact := strings.TrimSpace(p.SecurityContact); contact != "" {
		if !strings.Contains(contact, ":") && strings.Contains(contact, "@") {
			contact = "mailto:" + contact
		}
		refs = append(refs, cdx.ExternalReference{Type: cdx.ERTypeSecurityContact, URL: contact})
	}
	if disclosure := strings.TrimSpace(p.VulnerabilityDisclosureURL); disclosure != "" {
		refs = append(refs, cdx.ExternalReference{Type: cdx.ERTypeAdvisories, URL: disclosure, Comment: "Coordinated vulnerability disclosure policy"})
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

// knownExternalReferenceTypes is the CycloneDX externalReference type
// vocabulary understood by the encoder.
//
// An ingested document can carry any string here, and the library's
// version-downgrade pass only rewrites types it recognizes — an unknown string
// falls through and is emitted verbatim, producing a schema-invalid document.
// A type outside this set is rewritten to "other", which keeps the link while
// staying valid. Per-version narrowing (a 1.7 type emitted as 1.4) is then
// handled by the library.
var knownExternalReferenceTypes = map[string]struct{}{
	"adversary-model":           {},
	"advisories":                {},
	"attestation":               {},
	"bom":                       {},
	"build-meta":                {},
	"build-system":              {},
	"certification-report":      {},
	"chat":                      {},
	"citation":                  {},
	"codified-infrastructure":   {},
	"component-analysis-report": {},
	"configuration":             {},
	"digital-signature":         {},
	"distribution":              {},
	"distribution-intake":       {},
	"documentation":             {},
	"dynamic-analysis-report":   {},
	"electronic-signature":      {},
	"evidence":                  {},
	"exploitability-statement":  {},
	"formulation":               {},
	"issue-tracker":             {},
	"license":                   {},
	"log":                       {},
	"mailing-list":              {},
	"maturity-report":           {},
	"model-card":                {},
	"other":                     {},
	"patent":                    {},
	"patent-assertion":          {},
	"patent-family":             {},
	"pentest-report":            {},
	"poam":                      {},
	"quality-metrics":           {},
	"release-notes":             {},
	"rfc-9116":                  {},
	"risk-assessment":           {},
	"runtime-analysis-report":   {},
	"security-contact":          {},
	"social":                    {},
	"source-distribution":       {},
	"static-analysis-report":    {},
	"support":                   {},
	"threat-model":              {},
	"vcs":                       {},
	"vulnerability-assertion":   {},
	"website":                   {},
}

// externalReferenceType maps a preserved reference type onto the encoder
// vocabulary, falling back to "other" for anything unrecognized.
func externalReferenceType(value string) cdx.ExternalReferenceType {
	if _, ok := knownExternalReferenceTypes[strings.ToLower(strings.TrimSpace(value))]; ok {
		return cdx.ExternalReferenceType(strings.ToLower(strings.TrimSpace(value)))
	}
	return cdx.ERTypeOther
}

// referenceDigests validates the integrity assertion carried on an external
// reference. It uses the same gate as component hashes, so a malformed value
// cannot ride in on a reference instead.
func referenceDigests(hashes *[]cdx.Hash) []Digest {
	if hashes == nil {
		return nil
	}
	var out []Digest
	for _, hash := range *hashes {
		if digest, ok := ingestedDigest(string(hash.Algorithm), hash.Value); ok {
			out = append(out, digest)
		}
	}
	return out
}

// componentFromCycloneDX projects one CycloneDX component onto the neutral
// model. Both decode paths (the component inventory and the metadata-only
// fallback) share it so they cannot drift apart.
// registryRootMarker is the comment Bomly attaches to a distribution
// reference that names a registry rather than an exact artifact. Recognizing
// it on ingest is what keeps Bomly's own round trip honest: CycloneDX defines
// `distribution` as where the artifact can be obtained, so an unmarked
// reference is promoted to a download location, and without the marker a
// re-ingested "https://rubygems.org/" would be republished as one.
const registryRootMarker = "Registry root; not the exact artifact location"

func componentFromCycloneDX(comp cdx.Component) Component {
	component := Component{
		ID:          comp.BOMRef,
		Name:        comp.Name,
		Type:        string(comp.Type),
		Scope:       string(comp.Scope),
		Version:     comp.Version,
		PURL:        comp.PackageURL,
		Copyright:   comp.Copyright,
		Licenses:    parseCycloneDXLicenses(comp.Licenses),
		Description: comp.Description,
		Originator:  comp.Publisher,
	}
	// Store the trimmed value isValidCPE actually validated: a padded CPE
	// would otherwise pass the check and be re-emitted with its whitespace.
	if cpe := strings.TrimSpace(comp.CPE); isValidCPE(cpe) {
		component.CPEs = []string{cpe}
	}
	// The name is optional on a CycloneDX organizational entity. Gating the
	// whole block on it discarded the URLs and contacts of a supplier that
	// identifies itself only that way.
	if comp.Supplier != nil {
		if comp.Supplier.Name != "" {
			component.Supplier = comp.Supplier.Name
			component.SupplierType = "Organization"
		}
		if comp.Supplier.Contact != nil {
			for _, c := range *comp.Supplier.Contact {
				if c.Name == "" && c.Email == "" && c.Phone == "" {
					continue
				}
				// A contact email is republished verbatim, so it needs the
				// same validation a mailto reference gets — otherwise a
				// credential-shaped address passes straight through.
				email := c.Email
				if email != "" && !isEmailAddress(email) {
					email = ""
				}
				if c.Name == "" && email == "" && c.Phone == "" {
					continue
				}
				component.SupplierContacts = append(component.SupplierContacts, Contact{
					Name: c.Name, Email: email, Phone: c.Phone,
				})
			}
		}
		if comp.Supplier.URL != nil {
			for _, u := range *comp.Supplier.URL {
				if isPublishableReferenceURL(u) {
					// Store the trimmed value the gate actually validated.
					component.SupplierURLs = append(component.SupplierURLs, strings.TrimSpace(u))
				}
			}
		}
	}
	if comp.Hashes != nil {
		for _, hash := range *comp.Hashes {
			if digest, ok := ingestedDigest(string(hash.Algorithm), hash.Value); ok {
				component.Digests = append(component.Digests, digest)
			}
		}
	}
	if comp.ExternalReferences != nil {
		for _, ref := range *comp.ExternalReferences {
			switch ref.Type {
			case cdx.ERTypeDistribution:
				// A component may list several distribution URLs (mirrors).
				// The neutral model has one artifact slot, so the first
				// classified value takes it and the rest are preserved
				// verbatim rather than overwriting the earlier assertion.
				if component.ArtifactURL == "" && component.RegistryURL == "" {
					locator := classifyAssertedDownloadLocation(ref.URL)
					if strings.EqualFold(strings.TrimSpace(ref.Comment), registryRootMarker) &&
						locator.Kind == LocatorArtifact {
						// The producer said this is a registry, not the exact
						// artifact. Believe it rather than the path shape.
						locator.Kind = LocatorRegistryRoot
					}
					applyLocatorComment(&component, locator, ref.Comment, referenceDigests(ref.Hashes)...)
					if component.ArtifactURL != "" || component.RegistryURL != "" {
						continue
					}
				}
				if !isPublishableReferenceURL(ref.URL) {
					continue
				}
				component.ExternalRefs = append(component.ExternalRefs, ExternalRef{
					Type:    string(ref.Type),
					URL:     strings.TrimSpace(ref.URL),
					Comment: ref.Comment,
					Digests: referenceDigests(ref.Hashes),
				})
			case cdx.ERTypeVCS:
				// Untrusted input: gate and normalize it exactly like a
				// detector-supplied value, because it is re-emitted and also
				// becomes the SPDX download location. CycloneDX types this as
				// an array, so additional repositories are kept rather than
				// overwriting the first.
				vcs := classifyIngestedVCS(ref.URL)
				if vcs == "" {
					continue
				}
				if component.VCSURL == "" {
					component.VCSURL, component.VCSComment = vcs, ref.Comment
					component.VCSDigests = referenceDigests(ref.Hashes)
					continue
				}
				component.ExternalRefs = append(component.ExternalRefs, ExternalRef{
					Type:    string(ref.Type),
					URL:     vcs,
					Comment: ref.Comment,
					Digests: referenceDigests(ref.Hashes),
				})
			default:
				if !isPublishableReferenceURL(ref.URL) {
					continue
				}
				component.ExternalRefs = append(component.ExternalRefs, ExternalRef{
					Type:    string(ref.Type),
					URL:     strings.TrimSpace(ref.URL),
					Comment: ref.Comment,
					Digests: referenceDigests(ref.Hashes),
				})
			}
		}
	}
	return component
}

// cycloneDXComponentReferences builds the per-component external references:
// where the package came from, its source repository, and anything preserved
// from an ingested document.
//
// A registry root is emitted only when no exact artifact URL is known, and it
// carries a comment saying so — it names where the ecosystem fetches from, not
// where this package came from.
func cycloneDXComponentReferences(component Component) []cdx.ExternalReference {
	refs := make([]cdx.ExternalReference, 0, 3+len(component.ExternalRefs))

	switch {
	case component.ArtifactURL != "":
		artifact := cdx.ExternalReference{
			Type:    cdx.ERTypeDistribution,
			URL:     component.ArtifactURL,
			Comment: component.ArtifactComment,
		}
		if hashes := cycloneDXHashes(component.ArtifactDigests); len(hashes) > 0 {
			artifact.Hashes = &hashes
		}
		refs = append(refs, artifact)
	case component.RegistryURL != "":
		// Only explain the value when the producer said nothing: replacing a
		// source document's own comment could contradict what it asserted.
		registry := cdx.ExternalReference{
			Type:    cdx.ERTypeDistribution,
			URL:     component.RegistryURL,
			Comment: firstNonEmpty(component.RegistryComment, registryRootMarker),
		}
		if hashes := cycloneDXHashes(component.RegistryDigests); len(hashes) > 0 {
			registry.Hashes = &hashes
		}
		refs = append(refs, registry)
	}

	// VCSURL is detector-supplied and version-exact, so it wins over the
	// scorecard repository. Emitting both would assert the same repository
	// twice from two sources.
	if vcs := firstNonEmpty(component.VCSURL, component.Repository); vcs != "" {
		emitted := cdx.ExternalReference{Type: cdx.ERTypeVCS, URL: vcs, Comment: component.VCSComment}
		if hashes := cycloneDXHashes(component.VCSDigests); len(hashes) > 0 {
			emitted.Hashes = &hashes
		}
		refs = append(refs, emitted)
	}

	for _, ref := range component.ExternalRefs {
		emitted := cdx.ExternalReference{
			Type:    externalReferenceType(ref.Type),
			URL:     ref.URL,
			Comment: ref.Comment,
		}
		if hashes := cycloneDXHashes(ref.Digests); len(hashes) > 0 {
			emitted.Hashes = &hashes
		}
		refs = append(refs, emitted)
	}

	if len(refs) == 0 {
		return nil
	}
	return refs
}

// bareEmail returns value when it looks like a plain email address (no URI
// scheme), otherwise "".
func bareEmail(value string) string {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "@") && !strings.Contains(value, ":") && !strings.Contains(value, "/") {
		return value
	}
	return ""
}

// cycloneDXLifecyclePhase validates a lifecycle phase against the CycloneDX
// vocabulary, returning "" for unknown values so an invalid phase can never
// make the document non-conformant.
func cycloneDXLifecyclePhase(value string) cdx.LifecyclePhase {
	switch cdx.LifecyclePhase(strings.ToLower(strings.TrimSpace(value))) {
	case cdx.LifecyclePhaseDesign, cdx.LifecyclePhasePreBuild, cdx.LifecyclePhaseBuild,
		cdx.LifecyclePhasePostBuild, cdx.LifecyclePhaseOperations, cdx.LifecyclePhaseDiscovery,
		cdx.LifecyclePhaseDecommission:
		return cdx.LifecyclePhase(strings.ToLower(strings.TrimSpace(value)))
	default:
		return ""
	}
}

// cycloneDXAggregate validates a composition aggregate value, returning "" for
// unknown values.
func cycloneDXAggregate(value string) cdx.CompositionAggregate {
	switch cdx.CompositionAggregate(strings.ToLower(strings.TrimSpace(value))) {
	case cdx.CompositionAggregateComplete, cdx.CompositionAggregateIncomplete,
		cdx.CompositionAggregateIncompleteFirstPartyOnly, cdx.CompositionAggregateIncompleteFirstPartyOpenSourceOnly,
		cdx.CompositionAggregateIncompleteThirdPartyOnly, cdx.CompositionAggregateIncompleteThirdPartyOpenSourceOnly,
		cdx.CompositionAggregateNotSpecified, cdx.CompositionAggregateUnknown:
		return cdx.CompositionAggregate(strings.ToLower(strings.TrimSpace(value)))
	default:
		return ""
	}
}

func cycloneDXMetadataProperties(p Provenance) []cdx.Property {
	if strings.TrimSpace(p.SupportEnd) == "" {
		return nil
	}
	return []cdx.Property{{Name: "bomly:support_end_date", Value: strings.TrimSpace(p.SupportEnd)}}
}

func cycloneDXToolNames(metadata *cdx.Metadata) []string {
	if metadata == nil || metadata.Tools == nil {
		return nil
	}
	names := make([]string, 0)
	if metadata.Tools.Components != nil {
		for _, tool := range *metadata.Tools.Components {
			if strings.TrimSpace(tool.Name) != "" {
				names = append(names, tool.Name)
			}
		}
	}
	if metadata.Tools.Tools != nil {
		for _, tool := range *metadata.Tools.Tools {
			if strings.TrimSpace(tool.Name) != "" {
				names = append(names, tool.Name)
			}
		}
	}
	return names
}

func cycloneDXPrimaryToolName(metadata *cdx.Metadata) string {
	names := cycloneDXToolNames(metadata)
	if len(names) > 0 {
		return names[0]
	}
	return defaultToolName
}

func cycloneDXComponentType(value string) cdx.ComponentType {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "application":
		return cdx.ComponentTypeApplication
	case "framework":
		return cdx.ComponentTypeFramework
	case "container":
		return cdx.ComponentTypeContainer
	case "operating-system":
		return cdx.ComponentTypeOS
	case "device":
		return cdx.ComponentTypeDevice
	case "file":
		return cdx.ComponentTypeFile
	case "firmware":
		return cdx.ComponentTypeFirmware
	default:
		return cdx.ComponentTypeLibrary
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func cycloneDXScope(value string) cdx.Scope {
	switch value {
	case "runtime":
		return cdx.ScopeRequired
	case "development":
		return cdx.ScopeExcluded
	default:
		return ""
	}
}

func chooseRoot(doc *Document) *Component {
	if doc == nil || len(doc.Components) == 0 {
		return nil
	}
	if len(doc.Roots) > 0 {
		rootID := doc.Roots[0]
		for i := range doc.Components {
			if doc.Components[i].ID == rootID {
				return &doc.Components[i]
			}
		}
	}
	return &doc.Components[0]
}

func toCycloneDXVersion(target Target) cdx.SpecVersion {
	switch target {
	case TargetCycloneDX14JSON:
		return cdx.SpecVersion1_4
	case TargetCycloneDX15JSON:
		return cdx.SpecVersion1_5
	case TargetCycloneDX16JSON:
		return cdx.SpecVersion1_6
	default:
		return cdx.SpecVersion1_7
	}
}

func cycloneDXLicenses(licenses []License) cdx.Licenses {
	if len(licenses) == 0 {
		return nil
	}
	out := make(cdx.Licenses, 0, len(licenses))
	for _, license := range licenses {
		switch {
		case license.SPDXExpression != "":
			out = append(out, cdx.LicenseChoice{Expression: license.SPDXExpression})
		case license.Value != "":
			out = append(out, cdx.LicenseChoice{License: &cdx.License{Name: license.Value}})
		}
	}
	return out
}

func cycloneDXHashes(digests []Digest) []cdx.Hash {
	if len(digests) == 0 {
		return nil
	}
	out := make([]cdx.Hash, 0, len(digests))
	for _, d := range digests {
		alg := cycloneDXHashAlgorithm(d.Algorithm)
		if alg == "" || strings.TrimSpace(d.Value) == "" {
			continue
		}
		out = append(out, cdx.Hash{Algorithm: alg, Value: d.Value})
	}
	return out
}

// cycloneDXHashAlgorithm maps a digest algorithm string onto a CycloneDX hash
// algorithm constant. Returns "" when the algorithm is unsupported so the
// digest is dropped rather than emitting an invalid BOM.
func cycloneDXHashAlgorithm(algorithm string) cdx.HashAlgorithm {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "md5":
		return cdx.HashAlgoMD5
	case "sha1", "sha-1":
		return cdx.HashAlgoSHA1
	case "sha256", "sha-256":
		return cdx.HashAlgoSHA256
	case "sha384", "sha-384":
		return cdx.HashAlgoSHA384
	case "sha512", "sha-512":
		return cdx.HashAlgoSHA512
	case "streebog-256":
		return cdx.HashAlgoStreebog256
	case "streebog-512":
		return cdx.HashAlgoStreebog512
	case "blake3":
		return cdx.HashAlgoBlake3
	case "blake2b-256":
		return cdx.HashAlgoBlake2b_256
	case "blake2b-384":
		return cdx.HashAlgoBlake2b_384
	case "blake2b-512":
		return cdx.HashAlgoBlake2b_512
	case "sha3-256":
		return cdx.HashAlgoSHA3_256
	case "sha3-384":
		return cdx.HashAlgoSHA3_384
	case "sha3-512":
		return cdx.HashAlgoSHA3_512
	default:
		return ""
	}
}

func cycloneDXEOLProperties(eol *EOL) []cdx.Property {
	if eol == nil {
		return nil
	}
	props := make([]cdx.Property, 0, 3)
	props = append(props, cdx.Property{Name: "bomly:eol", Value: strconv.FormatBool(eol.EOL)})
	if eol.EOLDate != "" {
		props = append(props, cdx.Property{Name: "bomly:eol_date", Value: eol.EOLDate})
	}
	if eol.Cycle != "" {
		props = append(props, cdx.Property{Name: "bomly:eol_cycle", Value: eol.Cycle})
	}
	return props
}

// cycloneDXVulnerabilities flattens per-component vulnerabilities into the
// BOM-level vulnerabilities array, deduplicating by advisory ID and collecting
// every affected component BOMRef under Affects.
func cycloneDXVulnerabilities(components []Component) []cdx.Vulnerability {
	type accumulator struct {
		vuln  Vulnerability
		refs  []string
		order int
	}
	byID := make(map[string]*accumulator)
	order := 0
	for _, comp := range components {
		for _, v := range comp.Vulnerabilities {
			if strings.TrimSpace(v.ID) == "" {
				continue
			}
			acc, ok := byID[v.ID]
			if !ok {
				acc = &accumulator{vuln: v, order: order}
				order++
				byID[v.ID] = acc
			}
			acc.refs = append(acc.refs, comp.ID)
		}
	}
	if len(byID) == 0 {
		return nil
	}
	out := make([]cdx.Vulnerability, 0, len(byID))
	for _, acc := range byID {
		out = append(out, cycloneDXVulnerability(acc.vuln, acc.refs))
	}
	sort.Slice(out, func(i, j int) bool {
		return byID[out[i].ID].order < byID[out[j].ID].order
	})
	return out
}

func cycloneDXVulnerability(v Vulnerability, refs []string) cdx.Vulnerability {
	vuln := cdx.Vulnerability{
		ID:             v.ID,
		Description:    v.Description,
		Recommendation: v.Recommendation,
	}
	if v.Source != "" {
		vuln.Source = &cdx.Source{Name: v.Source}
	}
	if v.Score != nil || v.Severity != "" || v.Vector != "" {
		rating := cdx.VulnerabilityRating{
			Severity: cycloneDXSeverity(v.Severity),
			Method:   cdx.ScoringMethod(v.Method),
			Vector:   v.Vector,
		}
		if v.Score != nil {
			rating.Score = new(*v.Score)
		}
		if v.Source != "" {
			rating.Source = &cdx.Source{Name: v.Source}
		}
		ratings := []cdx.VulnerabilityRating{rating}
		vuln.Ratings = &ratings
	}
	if len(v.CWEs) > 0 {
		vuln.CWEs = new(append([]int(nil), v.CWEs...))
	}
	if len(v.Advisories) > 0 {
		advisories := make([]cdx.Advisory, 0, len(v.Advisories))
		for _, url := range v.Advisories {
			advisories = append(advisories, cdx.Advisory{URL: url})
		}
		vuln.Advisories = &advisories
	}
	if len(refs) > 0 {
		sorted := append([]string(nil), refs...)
		sort.Strings(sorted)
		affects := make([]cdx.Affects, 0, len(sorted))
		for _, ref := range sorted {
			affects = append(affects, cdx.Affects{Ref: ref})
		}
		vuln.Affects = &affects
	}
	return vuln
}

func cycloneDXSeverity(severity string) cdx.Severity {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return cdx.SeverityCritical
	case "high":
		return cdx.SeverityHigh
	case "medium", "moderate":
		return cdx.SeverityMedium
	case "low":
		return cdx.SeverityLow
	case "none":
		return cdx.SeverityNone
	case "info", "informational":
		return cdx.SeverityInfo
	default:
		return cdx.SeverityUnknown
	}
}

func parseCycloneDXLicenses(licenses *cdx.Licenses) []License {
	if licenses == nil || len(*licenses) == 0 {
		return nil
	}
	out := make([]License, 0, len(*licenses))
	for _, choice := range *licenses {
		switch {
		case choice.Expression != "":
			out = append(out, License{SPDXExpression: choice.Expression, Value: choice.Expression})
		case choice.License != nil:
			value := choice.License.ID
			if value == "" {
				value = choice.License.Name
			}
			out = append(out, License{Value: value, SPDXExpression: choice.License.ID})
		}
	}
	return out
}
