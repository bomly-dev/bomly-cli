package engine

import (
	"context"

	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

type Detector = model.Detector
type DetectorDescriptor = model.DetectorDescriptor
type ResolveGraphRequest = model.DetectionRequest
type ResolveGraphResult = model.DetectionResult
type DetectorFilter = model.DetectorFilter
type PackageManager = model.PackageManager
type Ecosystem = model.Ecosystem
type TargetMode = model.TargetMode
type ComponentQuery = model.DependencyQuery
type Scope = model.Scope

type Auditor = model.Auditor
type AuditorDescriptor = model.AuditorDescriptor
type AuditRequest = model.AuditRequest
type AuditResult = model.AuditResult

type Matcher = model.Matcher
type MatcherDescriptor = model.MatcherDescriptor
type MatchRequest = model.MatchRequest
type MatchResult = model.MatchResult

type ExecutionTarget = model.ExecutionTarget
type ExecutionTargetKind = model.ExecutionTargetKind
type Subproject = model.Subproject
type Finding = model.Finding
type RiskScore = model.RiskScore

const (
	PackageManagerUnknown           = model.PackageManagerUnknown
	PackageManagerNPM               = model.PackageManagerNPM
	PackageManagerMaven             = model.PackageManagerMaven
	PackageManagerGoMod             = model.PackageManagerGoMod
	PackageManagerGitHubActions     = model.PackageManagerGitHubActions
	PackageManagerRPM               = model.PackageManagerRPM
	PackageManagerAPK               = model.PackageManagerAPK
	PackageManagerSBOM              = model.PackageManagerSBOM
	PackageManagerCargo             = model.PackageManagerCargo
	EcosystemUnknown                = model.EcosystemUnknown
	EcosystemNPM                    = model.EcosystemNPM
	EcosystemMaven                  = model.EcosystemMaven
	EcosystemGo                     = model.EcosystemGo
	EcosystemGitHub                 = model.EcosystemGitHub
	EcosystemRPM                    = model.EcosystemRPM
	EcosystemAPK                    = model.EcosystemAPK
	EcosystemSBOM                   = model.EcosystemSBOM
	TargetModeFullGraph             = model.TargetModeFullGraph
	TargetModeComponent             = model.TargetModeComponent
	ExecutionTargetFilesystem       = model.ExecutionTargetFilesystem
	ExecutionTargetWorkingDirectory = model.ExecutionTargetWorkingDirectory
	ExecutionTargetContainerImage   = model.ExecutionTargetContainerImage
	ScopeRuntime                    = model.ScopeRuntime
	ScopeDevelopment                = model.ScopeDevelopment
)

func newTestRegistry() *Registry {
	registry := NewRegistry(RegistryConfigs{}, *zap.NewNop())
	return registry
}

func (f fakeMatcher) Ready() bool {
	return true
}

func (f fakeMatcher) Applicable(_ context.Context, _ MatchRequest) (bool, error) {
	return true, nil
}
