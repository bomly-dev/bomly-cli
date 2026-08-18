package sbom

import (
	"strings"

	"github.com/bomly-dev/bomly-sdk"
)

// Well-known Dependency.Metadata keys used to carry assertions from an
// ingested SBOM across the graph hop.
//
// Ingest is not a decode-then-encode pass: a document becomes an sdk.Graph
// (ToGraph), flows through the whole pipeline, and a fresh document is rebuilt
// from that graph (FromDepGraph). Anything not placed on the sdk.Dependency
// is therefore lost before export. Riding Dependency.Metadata follows the
// precedent set by sdk.SetDetectionLicenses and needs no SDK contract change.
const (
	metadataKeySupplier       = "bomly.sbom.supplier"
	metadataKeySupplierType   = "bomly.sbom.supplier_type"
	metadataKeySupplierURLs   = "bomly.sbom.supplier_urls"
	metadataKeyNoDownload     = "bomly.sbom.no_download_location"
	metadataKeySupplierPeople = "bomly.sbom.supplier_contacts"
	metadataKeyLocatorDigests = "bomly.sbom.locator_digests"
	metadataKeyOriginator     = "bomly.sbom.originator"
	metadataKeyOriginatorType = "bomly.sbom.originator_type"
	metadataKeyDescription    = "bomly.sbom.description"
	metadataKeySummary        = "bomly.sbom.summary"
	metadataKeyArtifactNote   = "bomly.sbom.artifact_comment"
	metadataKeyVCSNote        = "bomly.sbom.vcs_comment"
	metadataKeyRegistryNote   = "bomly.sbom.registry_comment"
	metadataKeyRepository     = "bomly.sbom.repository"
	metadataKeyArtifactURL    = "bomly.sbom.artifact_url"
	metadataKeyVCSURL         = "bomly.sbom.vcs_url"
	metadataKeyRegistryURL    = "bomly.sbom.registry_url"
	metadataKeyExternalRefs   = "bomly.sbom.external_refs"
)

// setIngestedMetadata stashes the assertions an ingested SBOM made about a
// component onto the graph node that replaces it.
func setIngestedMetadata(dep *sdk.Dependency, component Component) {
	if dep == nil {
		return
	}
	values := map[string]string{
		metadataKeySupplier:       component.Supplier,
		metadataKeySupplierType:   component.SupplierType,
		metadataKeyOriginator:     component.Originator,
		metadataKeyOriginatorType: component.OriginatorType,
		metadataKeyDescription:    component.Description,
		metadataKeySummary:        component.Summary,
		metadataKeyArtifactNote:   component.ArtifactComment,
		metadataKeyVCSNote:        component.VCSComment,
		metadataKeyRegistryNote:   component.RegistryComment,
		metadataKeyRepository:     component.Repository,
		metadataKeyArtifactURL:    component.ArtifactURL,
		metadataKeyVCSURL:         component.VCSURL,
		metadataKeyRegistryURL:    component.RegistryURL,
	}
	for key, value := range values {
		if value == "" {
			continue
		}
		if dep.Metadata == nil {
			dep.Metadata = make(map[string]any)
		}
		dep.Metadata[key] = value
	}

	if len(component.SupplierURLs) > 0 {
		urls := make([]any, 0, len(component.SupplierURLs))
		for _, u := range component.SupplierURLs {
			urls = append(urls, u)
		}
		if dep.Metadata == nil {
			dep.Metadata = make(map[string]any)
		}
		dep.Metadata[metadataKeySupplierURLs] = urls
	}
	if len(component.SupplierContacts) > 0 {
		people := make([]any, 0, len(component.SupplierContacts))
		for _, c := range component.SupplierContacts {
			people = append(people, map[string]any{"name": c.Name, "email": c.Email, "phone": c.Phone})
		}
		if dep.Metadata == nil {
			dep.Metadata = make(map[string]any)
		}
		dep.Metadata[metadataKeySupplierPeople] = people
	}
	if locators := map[string][]Digest{
		"artifact": component.ArtifactDigests,
		"vcs":      component.VCSDigests,
		"registry": component.RegistryDigests,
	}; len(locators["artifact"])+len(locators["vcs"])+len(locators["registry"]) > 0 {
		encoded := map[string]any{}
		for slot, digests := range locators {
			if len(digests) == 0 {
				continue
			}
			entries := make([]any, 0, len(digests))
			for _, digest := range digests {
				entries = append(entries, map[string]any{
					"algorithm": digest.Algorithm, "value": digest.Value,
				})
			}
			encoded[slot] = entries
		}
		if dep.Metadata == nil {
			dep.Metadata = make(map[string]any)
		}
		dep.Metadata[metadataKeyLocatorDigests] = encoded
	}
	if component.NoDownloadLocation {
		if dep.Metadata == nil {
			dep.Metadata = make(map[string]any)
		}
		dep.Metadata[metadataKeyNoDownload] = true
	}

	if len(component.ExternalRefs) == 0 {
		return
	}
	refs := make([]any, 0, len(component.ExternalRefs))
	for _, ref := range component.ExternalRefs {
		entry := map[string]any{
			"type":    ref.Type,
			"url":     ref.URL,
			"comment": ref.Comment,
		}
		if len(ref.Digests) > 0 {
			digests := make([]any, 0, len(ref.Digests))
			for _, digest := range ref.Digests {
				digests = append(digests, map[string]any{
					"algorithm": digest.Algorithm, "value": digest.Value,
				})
			}
			entry["digests"] = digests
		}
		refs = append(refs, entry)
	}
	if dep.Metadata == nil {
		dep.Metadata = make(map[string]any)
	}
	dep.Metadata[metadataKeyExternalRefs] = refs
}

// restoredLocator re-validates a locator recovered from Dependency.Metadata,
// returning "" when it is not publishable as the kind it claims to be.
func restoredLocator(value any, kind LocatorKind) string {
	raw, _ := value.(string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if kind == LocatorVCS {
		return validatedVCSLocator(raw)
	}
	locator := classifyAssertedReference(raw)
	if locator.Kind == LocatorNone {
		return ""
	}
	// An artifact slot may hold a value the classifier reads as a registry
	// root and vice versa; what matters is that it is publishable at all.
	return locator.URL
}

// applyIngestedMetadata restores assertions stashed by setIngestedMetadata.
//
// The ingested values win over anything Bomly derived: they are the source
// document's own claims, and re-exporting must not silently rewrite another
// producer's assertion. For the distribution fields this also repairs a
// deliberate loss of fidelity — ToGraph does not record DependencySource (see
// its comment), so re-classifying the round-tripped URL would be strictly
// worse information than the bucket the source document already chose.
//
// Values are read defensively: a future plugin hop would JSON-round-trip this
// map, so anything that does not type-assert is skipped rather than trusted.
func applyIngestedMetadata(component *Component, metadata map[string]any) {
	if component == nil || len(metadata) == 0 {
		return
	}

	targets := map[string]*string{
		metadataKeySupplier:       &component.Supplier,
		metadataKeySupplierType:   &component.SupplierType,
		metadataKeyOriginator:     &component.Originator,
		metadataKeyOriginatorType: &component.OriginatorType,
		metadataKeyDescription:    &component.Description,
		metadataKeySummary:        &component.Summary,
		metadataKeyArtifactNote:   &component.ArtifactComment,
		metadataKeyVCSNote:        &component.VCSComment,
		metadataKeyRegistryNote:   &component.RegistryComment,
		metadataKeyRepository:     &component.Repository,
	}
	for key, target := range targets {
		if value, ok := metadata[key].(string); ok && value != "" {
			*target = value
		}
	}

	// The three distribution fields move as a set: a partial overwrite could
	// leave a component claiming both an ingested artifact URL and a stale
	// derived registry root.
	//
	// Every value is re-validated rather than trusted. Dependency.Metadata is
	// not private to the SBOM detector — any detector, including an external
	// plugin, can set these keys — so an unchecked assignment here would let
	// "file:///home/runner/secret" or a credential-bearing URL overwrite a
	// locator that just passed the classifier and reach the published
	// document. Restoring is an ingest path, so the assertion-level gate
	// applies, matching how these values were validated on the way in.
	artifact := restoredLocator(metadata[metadataKeyArtifactURL], LocatorArtifact)
	vcs := restoredLocator(metadata[metadataKeyVCSURL], LocatorVCS)
	registry := restoredLocator(metadata[metadataKeyRegistryURL], LocatorRegistryRoot)
	if artifact != "" || vcs != "" || registry != "" {
		component.ArtifactURL, component.VCSURL, component.RegistryURL = artifact, vcs, registry
	}

	if urls, ok := metadata[metadataKeySupplierURLs].([]any); ok {
		for _, entry := range urls {
			if value, ok := entry.(string); ok && value != "" {
				component.SupplierURLs = unionStrings(component.SupplierURLs, []string{value})
			}
		}
	}
	if people, ok := metadata[metadataKeySupplierPeople].([]any); ok {
		for _, entry := range people {
			fields, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			name, _ := fields["name"].(string)
			email, _ := fields["email"].(string)
			phone, _ := fields["phone"].(string)
			if name == "" && email == "" && phone == "" {
				continue
			}
			component.SupplierContacts = unionContacts(component.SupplierContacts,
				[]Contact{{Name: name, Email: email, Phone: phone}})
		}
	}
	if encoded, ok := metadata[metadataKeyLocatorDigests].(map[string]any); ok {
		targets := map[string]*[]Digest{
			"artifact": &component.ArtifactDigests,
			"vcs":      &component.VCSDigests,
			"registry": &component.RegistryDigests,
		}
		for slot, target := range targets {
			entries, ok := encoded[slot].([]any)
			if !ok {
				continue
			}
			for _, entry := range entries {
				fields, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				algorithm, _ := fields["algorithm"].(string)
				value, _ := fields["value"].(string)
				if digest, ok := ingestedDigest(algorithm, value); ok {
					*target = unionComponentDigests(*target, []Digest{digest})
				}
			}
		}
	}
	if none, ok := metadata[metadataKeyNoDownload].(bool); ok && none {
		component.NoDownloadLocation = true
	}

	raw, ok := metadata[metadataKeyExternalRefs].([]any)
	if !ok {
		return
	}
	refs := make([]ExternalRef, 0, len(raw))
	for _, entry := range raw {
		fields, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		refType, _ := fields["type"].(string)
		refURL, _ := fields["url"].(string)
		comment, _ := fields["comment"].(string)
		if refType == "" || refURL == "" {
			continue
		}
		restored := ExternalRef{Type: refType, URL: refURL, Comment: comment}
		if rawDigests, ok := fields["digests"].([]any); ok {
			for _, entry := range rawDigests {
				digestFields, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				algorithm, _ := digestFields["algorithm"].(string)
				value, _ := digestFields["value"].(string)
				if digest, ok := ingestedDigest(algorithm, value); ok {
					restored.Digests = append(restored.Digests, digest)
				}
			}
		}
		refs = append(refs, restored)
	}
	if len(refs) > 0 {
		component.ExternalRefs = refs
	}
}
