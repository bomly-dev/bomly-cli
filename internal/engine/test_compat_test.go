package engine

import (
	"context"

	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

type Detector = sdk.Detector
type DetectorDescriptor = sdk.DetectorDescriptor
type ResolveGraphRequest = sdk.DetectionRequest
type ResolveGraphResult = sdk.DetectionResult
type DetectorFilter = sdk.DetectorFilter
type PackageManager = sdk.PackageManager
type Ecosystem = sdk.Ecosystem
type ComponentQuery = sdk.DependencyQuery
type Scope = sdk.Scope

type Auditor = sdk.Auditor
type AuditorDescriptor = sdk.AuditorDescriptor
type AuditRequest = sdk.AuditRequest
type AuditResult = sdk.AuditResult

type Matcher = sdk.Matcher
type MatcherDescriptor = sdk.MatcherDescriptor
type MatchRequest = sdk.MatchRequest

type ExecutionTarget = sdk.ExecutionTarget
type ExecutionTargetKind = sdk.ExecutionTargetKind
type Subproject = sdk.Subproject
type Finding = sdk.Finding
type RiskScore = sdk.RiskScore

const (
	PackageManagerUnknown           = sdk.PackageManagerUnknown
	PackageManagerNPM               = sdk.PackageManagerNPM
	PackageManagerMaven             = sdk.PackageManagerMaven
	PackageManagerGoMod             = sdk.PackageManagerGoMod
	PackageManagerGitHubActions     = sdk.PackageManagerGitHubActions
	PackageManagerRPM               = sdk.PackageManagerRPM
	PackageManagerAPK               = sdk.PackageManagerAPK
	PackageManagerSBOM              = sdk.PackageManagerSBOM
	PackageManagerCargo             = sdk.PackageManagerCargo
	EcosystemUnknown                = sdk.EcosystemUnknown
	EcosystemNPM                    = sdk.EcosystemNPM
	EcosystemMaven                  = sdk.EcosystemMaven
	EcosystemGo                     = sdk.EcosystemGo
	EcosystemGitHub                 = sdk.EcosystemGitHub
	EcosystemRPM                    = sdk.EcosystemRPM
	EcosystemAPK                    = sdk.EcosystemAPK
	EcosystemSBOM                   = sdk.EcosystemSBOM
	ExecutionTargetFilesystem       = sdk.ExecutionTargetFilesystem
	ExecutionTargetWorkingDirectory = sdk.ExecutionTargetWorkingDirectory
	ExecutionTargetContainerImage   = sdk.ExecutionTargetContainerImage
	ScopeRuntime                    = sdk.ScopeRuntime
	ScopeDevelopment                = sdk.ScopeDevelopment
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
