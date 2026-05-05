package sdk

// ConsolidatedSubproject describes one subproject included in a consolidated graph.
type ConsolidatedSubproject struct {
	Subproject      Subproject
	DetectorName    string
	RootManifestIDs []string
}

// ConsolidatedManifest describes one selected manifest after detector-level
// deduplication and precedence rules have been applied.
type ConsolidatedManifest struct {
	Entry          GraphEntry
	Subproject     Subproject
	DetectorName   string
	Origin         DetectorOrigin
	Technique      DetectorTechnique
	RootManifestID string
}

// ConsolidatedGraph describes a merged view above per-subproject graph results.
type ConsolidatedGraph struct {
	ExecutionTarget ExecutionTarget
	Graphs          *GraphContainer
	Manifests       []ConsolidatedManifest
	Subprojects     []ConsolidatedSubproject
}
