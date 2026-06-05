package sdk

// DetectorOrigin describes where a detector, matcher, or auditor is sourced from.
type DetectorOrigin string

const (
	// CoreOrigin identifies components implemented directly in Bomly's own codebase.
	CoreOrigin DetectorOrigin = "core"
	// BundledOrigin identifies third-party components that are compiled into the Bomly binary (e.g. Syft, Grype).
	BundledOrigin DetectorOrigin = "bundled"
	// ExternalOrigin identifies components loaded as external plugins at runtime.
	ExternalOrigin DetectorOrigin = "external"
)

// DetectorTechnique describes the resolution strategy used by a detector.
// Only meaningful for detectors; matchers and auditors leave this empty.
type DetectorTechnique string

const (
	// ManifestTechnique reads a declarative dependency manifest file (e.g. package.json, Gemfile).
	ManifestTechnique DetectorTechnique = "manifest"
	// LockfileTechnique parses a deterministic lockfile (e.g. package-lock.json, yarn.lock).
	LockfileTechnique DetectorTechnique = "lockfile"
	// BuildToolTechnique invokes a build tool to resolve the live dependency graph.
	BuildToolTechnique DetectorTechnique = "build-tool"
	// SBOMTechnique ingests an existing SBOM document.
	SBOMTechnique DetectorTechnique = "sbom"
	// BinaryTechnique analyses a compiled binary or installed artifact.
	BinaryTechnique DetectorTechnique = "binary"
	// ContainerTechnique inspects a container image.
	ContainerTechnique DetectorTechnique = "container"
	// MultipleTechnique applies several of the above strategies depending on the target.
	MultipleTechnique DetectorTechnique = "multiple"
)
