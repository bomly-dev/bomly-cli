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
	DisplayName         string           `json:"displayName,omitempty"`
	Aliases             []string         `json:"aliases,omitempty"`
	Tags                []string         `json:"tags,omitempty"`
	SupportedEcosystems []Ecosystem      `json:"supportedEcosystems,omitempty"`
	SupportedManagers   []PackageManager `json:"supportedManagers,omitempty"`
}

// MatchRequest defines input for a matcher. Matchers enrich the package
// Registry keyed by PURL; the dependency Graph provides identity and structure.
type MatchRequest struct {
	ProjectPath     string           `json:"projectPath,omitempty"`
	ExecutionTarget ExecutionTarget  `json:"executionTarget"`
	SubprojectInfo  Subproject       `json:"subprojectInfo"`
	Ecosystem       Ecosystem        `json:"ecosystem,omitempty"`
	PackageManager  PackageManager   `json:"packageManager,omitempty"`
	Query           PackageQuery     `json:"query"`
	Graph           *Graph           `json:"graph,omitempty"`
	Registry        *PackageRegistry `json:"registry,omitempty"`
	Target          *Dependency      `json:"target,omitempty"`
	MatcherFilter   MatcherFilter    `json:"matcherFilter"`
	Stderr          io.Writer        `json:"-"`
}

// MatchResult contains the package registry after matcher enrichment.
type MatchResult struct {
	Registry     *PackageRegistry `json:"registry,omitempty"`
	MatcherStats MatcherStats     `json:"matcherStats,omitempty"`
}

// MatcherStats describes one completed matcher run and optional summary counts.
type MatcherStats struct {
	Name              string `json:"name"`
	DisplayName       string `json:"displayName,omitempty"`
	MatchedPackages   int    `json:"matchedPackages,omitempty"`
	UnmatchedPackages int    `json:"unmatchedPackages,omitempty"`
	Licenses          int    `json:"licenses,omitempty"`
	Vulnerabilities   int    `json:"vulnerabilities,omitempty"`
}

// Matcher enriches registry packages with license and vulnerability data.
type Matcher interface {
	Descriptor() MatcherDescriptor
	Ready() bool
	Applicable(context.Context, MatchRequest) (bool, error)
	Match(context.Context, MatchRequest) (MatchResult, error)
}

// MatchResponse is the matcher response payload exposed to plugins.
//
// It aliases MatchResult so plugin code can name payload types by role while
// sharing the same transport shape Bomly core uses internally.
type MatchResponse = MatchResult
