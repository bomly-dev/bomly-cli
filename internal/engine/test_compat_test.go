package engine

import (
	"context"

	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

type Detector = plugin.Detector
type DetectorDescriptor = plugin.DetectorDescriptor
type ResolveGraphRequest = plugin.DetectionRequest
type ResolveGraphResult = plugin.DetectionResult
type DetectorFilter = plugin.DetectorFilter
type PackageManager = model.PackageManager
type Ecosystem = model.Ecosystem

type AuditorDescriptor = plugin.AuditorDescriptor
type AuditRequest = plugin.AuditRequest
type AuditResult = plugin.AuditResult

type MatcherDescriptor = plugin.MatcherDescriptor
type MatchRequest = plugin.MatchRequest

type ExecutionTarget = plugin.ExecutionTarget
type Subproject = plugin.Subproject
type Finding = model.Finding
type RiskScore = model.RiskScore

const (
	PackageManagerUnknown           = model.PackageManagerUnknown
	PackageManagerNPM               = model.PackageManagerNPM
	PackageManagerPNPM              = model.PackageManagerPNPM
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
	ExecutionTargetFilesystem       = plugin.ExecutionTargetFilesystem
	ExecutionTargetWorkingDirectory = plugin.ExecutionTargetWorkingDirectory
	ExecutionTargetContainerImage   = plugin.ExecutionTargetContainerImage
	ScopeRuntime                    = model.ScopeRuntime
	ScopeDevelopment                = model.ScopeDevelopment
)

func newTestRegistry() *Registry {
	registry := NewRegistry(RegistryConfigs{}, *zap.NewNop())
	return registry
}

func (f fakeMatcher) Ready(context.Context, MatchRequest) error {
	return nil
}

func (f fakeMatcher) Applicable(_ context.Context, _ MatchRequest) (bool, error) {
	return true, nil
}
