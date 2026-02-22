package sdk

// ComponentType distinguishes detector and auditor implementation families.
type ComponentType string

const (
	NativeComponent         ComponentType = "native"
	LockfileParserComponent ComponentType = "lockfile-parser"
	ThirdPartyComponent     ComponentType = "third-party"
	PluginComponent         ComponentType = "plugin"

	// ComponentTypeNative identifies native built-in components.
	ComponentTypeNative = NativeComponent
	// ComponentTypeLockfileParser identifies lockfile parser components.
	ComponentTypeLockfileParser = LockfileParserComponent
	// ComponentTypeThirdParty identifies third-party-backed components.
	ComponentTypeThirdParty = ThirdPartyComponent
	// ComponentTypePlugin identifies externally managed plugin components.
	ComponentTypePlugin = PluginComponent
)

// TargetMode describes whether an operation targets a whole graph or a single component.
type TargetMode string

const (
	// TargetModeFullGraph requests whole-project resolution or analysis.
	TargetModeFullGraph TargetMode = "full-graph"
	// TargetModeComponent requests a single-component targeted query.
	TargetModeComponent TargetMode = "component"
)
