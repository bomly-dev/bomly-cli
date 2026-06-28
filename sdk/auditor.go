package sdk

import (
	"context"
	"io"
)

// AuditorFilter narrows auditor selection for a request.
type AuditorFilter struct {
	Include []string
	Exclude []string
}

// Includes reports whether an auditor name is explicitly allowed.
func (f AuditorFilter) Includes(name string) bool {
	return includesName(f.Include, name)
}

// Excludes reports whether an auditor name is explicitly denied.
func (f AuditorFilter) Excludes(name string) bool {
	return excludesName(f.Exclude, name)
}

// AuditRequest defines input for an auditor. Auditors read the dependency Graph
// and the package Registry and emit reference-style findings.
type AuditRequest struct {
	ProjectPath     string           `json:"projectPath,omitempty"`
	ExecutionTarget ExecutionTarget  `json:"executionTarget"`
	SubprojectInfo  Subproject       `json:"subprojectInfo"`
	Ecosystem       Ecosystem        `json:"ecosystem,omitempty"`
	PackageManager  PackageManager   `json:"packageManager,omitempty"`
	Query           PackageQuery     `json:"query"`
	Graph           *Graph           `json:"graph,omitempty"`
	BaselineGraph   *Graph           `json:"baselineGraph,omitempty"`
	Registry        *PackageRegistry `json:"registry,omitempty"`
	Target          *Dependency      `json:"target,omitempty"`
	AuditorFilter   AuditorFilter    `json:"auditorFilter"`
	Stderr          io.Writer        `json:"-"`
}

// AuditResult contains findings and scores from one auditor.
type AuditResult struct {
	Findings        []Finding      `json:"findings,omitempty"`
	RiskScores      []RiskScore    `json:"riskScores,omitempty"`
	AuditorRuns     []string       `json:"auditorRuns,omitempty"`
	AuditorFindings map[string]int `json:"auditorFindings,omitempty"`
}

// AuditorDescriptor describes an auditor registration.
type AuditorDescriptor struct {
	Name                string           `json:"name"`
	DisplayName         string           `json:"displayName,omitempty"`
	Aliases             []string         `json:"aliases,omitempty"`
	Tags                []string         `json:"tags,omitempty"`
	SupportedEcosystems []Ecosystem      `json:"supportedEcosystems,omitempty"`
	SupportedManagers   []PackageManager `json:"supportedManagers,omitempty"`
}

// Auditor analyzes graphs or components and returns findings.
type Auditor interface {
	Descriptor() AuditorDescriptor
	// Ready reports whether the auditor can run for the given request. It
	// returns nil when ready and a non-nil error describing the reason
	// otherwise. Implementations may perform lightweight, cancellable I/O and
	// should honor ctx.
	Ready(context.Context, AuditRequest) error
	Applicable(context.Context, AuditRequest) (bool, error)
	Audit(context.Context, AuditRequest) (AuditResult, error)
}

// AuditResponse is the auditor response payload exposed to plugins.
//
// It aliases AuditResult so plugin code can name payload types by role while
// sharing the same transport shape Bomly core uses internally.
type AuditResponse = AuditResult
