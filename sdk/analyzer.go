package sdk

import (
	"context"
	"io"
)

// AnalyzerFilter narrows analyzer selection for a request.
type AnalyzerFilter struct {
	Include []string
	Exclude []string
}

// Includes reports whether an analyzer name is explicitly allowed.
func (f AnalyzerFilter) Includes(name string) bool {
	return includesName(f.Include, name)
}

// Excludes reports whether an analyzer name is explicitly denied.
func (f AnalyzerFilter) Excludes(name string) bool {
	return excludesName(f.Exclude, name)
}

// AnalyzerDescriptor describes an analyzer registration.
type AnalyzerDescriptor struct {
	Name                string           `json:"name"`
	Enabled             bool             `json:"enabled,omitempty"`
	Origin              DetectorOrigin   `json:"origin,omitempty"`
	SupportedEcosystems []Ecosystem      `json:"supportedEcosystems,omitempty"`
	SupportedManagers   []PackageManager `json:"supportedManagers,omitempty"`
	// SupportedLanguages is the analyzer's primary dispatch axis.
	SupportedLanguages []Language   `json:"supportedLanguages,omitempty"`
	SupportedModes     []TargetMode `json:"supportedModes,omitempty"`
	// SupportedTiers communicates the precision the analyzer can deliver.
	SupportedTiers []ReachabilityTier `json:"supportedTiers,omitempty"`
	Priority       int                `json:"priority,omitempty"`
}

// AnalyzeRequest defines input for an analyzer. Analyzers annotate
// Vulnerability.Reachability on packages in the Registry.
type AnalyzeRequest struct {
	ProjectPath     string           `json:"projectPath,omitempty"`
	ExecutionTarget ExecutionTarget  `json:"executionTarget"`
	SubprojectInfo  Subproject       `json:"subprojectInfo"`
	Ecosystem       Ecosystem        `json:"ecosystem,omitempty"`
	PackageManager  PackageManager   `json:"packageManager,omitempty"`
	Language        Language         `json:"language,omitempty"`
	Mode            TargetMode       `json:"mode,omitempty"`
	Query           PackageQuery     `json:"query"`
	Graph           *Graph           `json:"graph,omitempty"`
	Registry        *PackageRegistry `json:"registry,omitempty"`
	Target          *Dependency      `json:"target,omitempty"`
	AnalyzerFilter  AnalyzerFilter   `json:"analyzerFilter"`
	Stderr          io.Writer        `json:"-"`
}

// ReachabilityStats tallies the per-analyzer outcome distribution.
type ReachabilityStats struct {
	Reachable     int `json:"reachable,omitempty"`
	Unreachable   int `json:"unreachable,omitempty"`
	Unknown       int `json:"unknown,omitempty"`
	NotApplicable int `json:"not_applicable,omitempty"`
}

// AnalyzeResult contains the registry after analyzer enrichment.
type AnalyzeResult struct {
	Registry      *PackageRegistry             `json:"registry,omitempty"`
	AnalyzerRuns  []string                     `json:"analyzerRuns,omitempty"`
	AnalyzerStats map[string]ReachabilityStats `json:"analyzerStats,omitempty"`
}

// Analyzer enriches Vulnerability entries with reachability data derived from
// code analysis. Analyzers run after matchers, before auditors, and must never
// abort the pipeline on failure.
type Analyzer interface {
	Descriptor() AnalyzerDescriptor
	Ready() bool
	Applicable(context.Context, AnalyzeRequest) (bool, error)
	Analyze(context.Context, AnalyzeRequest) (AnalyzeResult, error)
}

// AnalyzeResponse is the analyzer response payload exposed to plugins.
type AnalyzeResponse = AnalyzeResult
