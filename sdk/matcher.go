package sdk

import (
	"context"
	"io"
)

// MatcherFilter narrows matcher selection for a request.
type MatcherFilter struct {
	Include []string
	Exclude []string
}

// Includes reports whether a matcher name is explicitly allowed.
func (f MatcherFilter) Includes(name string) bool {
	return includesName(f.Include, name)
}

// Excludes reports whether a matcher name is explicitly denied.
func (f MatcherFilter) Excludes(name string) bool {
	return excludesName(f.Exclude, name)
}

// MatcherDescriptor describes a matcher registration.
type MatcherDescriptor struct {
	Name                string           `json:"name"`
	Enabled             bool             `json:"enabled,omitempty"`
	ComponentType       ComponentType    `json:"componentType,omitempty"`
	SupportedEcosystems []Ecosystem      `json:"supportedEcosystems,omitempty"`
	SupportedManagers   []PackageManager `json:"supportedManagers,omitempty"`
	SupportedModes      []TargetMode     `json:"supportedModes,omitempty"`
	Priority            int              `json:"priority,omitempty"`
	Required            bool             `json:"required,omitempty"`
	Capabilities        []string         `json:"capabilities,omitempty"`
}

// MatchRequest defines input for a matcher.
type MatchRequest struct {
	ProjectPath     string          `json:"projectPath,omitempty"`
	ExecutionTarget ExecutionTarget `json:"executionTarget"`
	SubprojectInfo  Subproject      `json:"subprojectInfo"`
	Ecosystem       Ecosystem       `json:"ecosystem,omitempty"`
	PackageManager  PackageManager  `json:"packageManager,omitempty"`
	Mode            TargetMode      `json:"mode,omitempty"`
	Query           PackageQuery    `json:"query"`
	Graph           *Graph          `json:"graph,omitempty"`
	Target          *Package        `json:"target,omitempty"`
	MatcherFilter   MatcherFilter   `json:"matcherFilter"`
	Stderr          io.Writer       `json:"-"`
}

// MatchResult contains the graph after matcher enrichment.
type MatchResult struct {
	Graph       *Graph   `json:"graph,omitempty"`
	Target      *Package `json:"target,omitempty"`
	MatcherRuns []string `json:"matcherRuns,omitempty"`
}

// Matcher enriches graph packages with license data.
type Matcher interface {
	Descriptor() MatcherDescriptor
	Ready() bool
	Applicable(context.Context, MatchRequest) (bool, error)
	Match(context.Context, MatchRequest) (MatchResult, error)
}

// MatchResponse is the matcher response payload exposed to plugins.
type MatchResponse = MatchResult
