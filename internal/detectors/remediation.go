package detectors

import (
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// RemediationAdvice builds manager-specific, read-only guidance for a strategy.
// Concrete detectors own this function and the wording it returns.
type RemediationAdvice func(
	action sdk.RemediationAction,
	name, version, manifestPath string,
) string

// BuildRemediationHints assembles occurrence-scoped hints from a detector's
// graph. It handles only common graph traversal; the calling detector owns its
// advertised actions and manager-specific advice.
func BuildRemediationHints(
	request sdk.RemediationHintRequest,
	manager sdk.PackageManager,
	actions []sdk.RemediationAction,
	advice RemediationAdvice,
) sdk.RemediationHintResponse {
	if request.Detection.Graphs == nil || request.Registry == nil || len(actions) == 0 {
		return sdk.RemediationHintResponse{}
	}
	advertised := make(map[sdk.RemediationAction]struct{}, len(actions))
	for _, action := range actions {
		advertised[action] = struct{}{}
	}

	response := sdk.RemediationHintResponse{}
	for _, entry := range request.Detection.Graphs.Entries {
		if entry.Graph == nil {
			continue
		}
		for _, dependency := range entry.Graph.Nodes() {
			if dependency == nil {
				continue
			}
			packageRef := dependency.PackageRef
			if packageRef == "" {
				packageRef = sdk.CanonicalPackageURLFromDependency(dependency)
			}
			if packageRef == "" {
				continue
			}
			pkg, ok := request.Registry.Get(packageRef)
			if !ok || pkg == nil || pkg.Remediation == nil ||
				pkg.Remediation.Status != sdk.PackageRemediationComplete ||
				strings.TrimSpace(pkg.Remediation.RecommendedVersion) == "" {
				continue
			}
			dependencyManager := dependency.PackageManager
			if dependencyManager == sdk.PackageManagerUnknown {
				dependencyManager = request.Detection.SubprojectInfo.PrimaryPackageManager()
			}
			if dependencyManager != manager {
				continue
			}
			hint := sdk.RemediationHint{
				DependencyRef: dependency.ID,
				ManifestPath:  entry.Manifest.Path,
			}
			for _, action := range remediationActionOrder {
				if _, ok := advertised[action]; !ok {
					continue
				}
				strategy := sdk.RemediationStrategyHint{
					Action: action,
				}
				if advice != nil {
					strategy.Advice = advice(
						action,
						dependency.DisplayName(),
						pkg.Remediation.RecommendedVersion,
						entry.Manifest.Path,
					)
				}
				hint.Strategies = append(hint.Strategies, strategy)
			}
			if len(hint.Strategies) > 0 {
				response.Hints = append(response.Hints, hint)
			}
		}
	}
	return response
}

var remediationActionOrder = []sdk.RemediationAction{
	sdk.RemediationActionDirectBump,
	sdk.RemediationActionTransitiveOverride,
	sdk.RemediationActionLockfileRefresh,
}
