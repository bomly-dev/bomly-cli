package sbom

import (
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
		refs = append(refs, map[string]any{
			"type":    ref.Type,
			"url":     ref.URL,
			"comment": ref.Comment,
		})
	}
	if dep.Metadata == nil {
		dep.Metadata = make(map[string]any)
	}
	dep.Metadata[metadataKeyExternalRefs] = refs
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
	artifact, _ := metadata[metadataKeyArtifactURL].(string)
	vcs, _ := metadata[metadataKeyVCSURL].(string)
	registry, _ := metadata[metadataKeyRegistryURL].(string)
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
		refs = append(refs, ExternalRef{Type: refType, URL: refURL, Comment: comment})
	}
	if len(refs) > 0 {
		component.ExternalRefs = refs
	}
}
