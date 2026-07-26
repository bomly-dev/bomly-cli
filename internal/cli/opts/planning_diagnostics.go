package opts

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// discoveryDiagnostics explains, per probed manifest candidate, why discovery
// did not turn it into a subproject. It replays the checks planning performed,
// in planning order — recursion scope, depth cap, exclude globs, ecosystem and
// detector filters, detector registration — so the discovery hot path stays
// free of diagnostic bookkeeping. The replay runs only on the
// "no subprojects discovered" failure path, over the probe's bounded
// candidate list.
//
// Detector readiness is deliberately not replayed here: planning never probes
// readiness (chains are planned statically and probed when they resolve), so a
// candidate that clears every check above is planned and cannot reach this
// error. Missing toolchains surface on the resolution path instead
// (internal/engine/pipeline_resolve.go, "no usable detector").
//
// A nil *discoveryDiagnostics is valid and reports no reasons; the exported
// DescribeDiscovery probe has no request context to replay.
type discoveryDiagnostics struct {
	req      Request
	planning *engine.Registry
	excludes []string
}

// newDiscoveryDiagnostics binds the planning registry (already narrowed by the
// active filters) and the request that produced the failure.
func newDiscoveryDiagnostics(registryValue *engine.Registry, req Request) *discoveryDiagnostics {
	return &discoveryDiagnostics{
		req:      req,
		planning: registryValue,
		excludes: normalizeExcludeGlobs(req.ExcludeGlobs),
	}
}

// skipReason returns a short explanation of why the candidate manifest in dir
// (root-relative rel, owned by manager) was not planned, or "" when the
// diagnostics cannot attribute a reason.
func (d *discoveryDiagnostics) skipReason(dir, rel string, manager sdk.PackageManager) string {
	if d == nil {
		return ""
	}
	if reason := d.scopeSkipReason(rel); reason != "" {
		return reason
	}
	if reason := d.ecosystemSkipReason(manager); reason != "" {
		return reason
	}
	return d.detectorSkipReason(dir, manager)
}

// scopeSkipReason reports candidates the discovery walk never inspected:
// nested directories on a non-recursive run, and directories below the depth
// cap or behind an exclude glob on a recursive one.
func (d *discoveryDiagnostics) scopeSkipReason(rel string) string {
	if !d.req.Recursive {
		if rel != "." && rel != "" {
			return "not scanned without --recursive"
		}
		return ""
	}
	if d.req.MaxDepth > 0 && discoveryDepth(rel) > d.req.MaxDepth {
		return fmt.Sprintf("below --max-depth %d", d.req.MaxDepth)
	}
	if pattern, ok := d.excludedPath(rel); ok {
		return fmt.Sprintf("excluded by --exclude %s", pattern)
	}
	return ""
}

// excludedPath reports whether rel or any of its ancestors matches an exclude
// glob; the recursive walk prunes the whole subtree at the first match.
func (d *discoveryDiagnostics) excludedPath(rel string) (string, bool) {
	if len(d.excludes) == 0 || rel == "." || rel == "" {
		return "", false
	}
	segments := strings.Split(rel, "/")
	for i := range segments {
		candidate := strings.Join(segments[:i+1], "/")
		if pattern, ok := matchExcludeGlob(d.excludes, candidate, path.Base(candidate)); ok {
			return pattern, true
		}
	}
	return "", false
}

// ecosystemSkipReason reports candidates dropped by --ecosystems.
func (d *discoveryDiagnostics) ecosystemSkipReason(manager sdk.PackageManager) string {
	ecosystem := manager.Ecosystem()
	filter := d.req.EcosystemFilter
	if len(filter.Include) > 0 && !filter.Includes(ecosystem) {
		return fmt.Sprintf("excluded by --ecosystems %s", strings.Join(sortedEcosystemNames(filter.Include, ""), ","))
	}
	if len(filter.Exclude) > 0 && filter.Excludes(ecosystem) {
		return fmt.Sprintf("excluded by --ecosystems -%s", ecosystem)
	}
	return ""
}

// detectorSkipReason reports candidates with no registered detector, with
// every candidate detector filtered out, or whose manifest planning could not
// resolve. Registration is checked against the request's unfiltered registry
// and selection against the filtered planning registry, so "no detector
// registered" stays distinguishable from "your filter removed them all".
func (d *discoveryDiagnostics) detectorSkipReason(dir string, manager sdk.PackageManager) string {
	if d.planning == nil {
		return ""
	}

	registryValue := d.req.Registry
	if registryValue == nil {
		registryValue = d.planning
	}
	candidates := detectorNamesForPackageManager(registryValue, d.req.ExecutionTarget.Kind, dir, manager)
	if len(candidates) == 0 {
		return fmt.Sprintf("no detector registered for %s", manager.Name())
	}

	chain := expandDetectorNames(d.planning, d.planning.PlannedDetectors(sdk.DetectionRequest{
		ProjectPath:     dir,
		ExecutionTarget: d.req.ExecutionTarget,
		Ecosystem:       manager.Ecosystem(),
		PackageManager:  manager,
		DetectorFilter:  d.req.DetectorFilter,
	}, candidates))
	if len(chain) == 0 {
		return fmt.Sprintf("detector filter excludes every %s detector (%s)", manager.Name(), strings.Join(candidates, ", "))
	}

	if _, ok := plannedSubprojectForPackageManager(
		d.planning,
		d.req.ExecutionTarget,
		dir,
		manager,
		nil,
		d.req.DetectorFilter,
	); !ok {
		return fmt.Sprintf("no resolvable %s manifest in this directory", manager.Name())
	}
	return ""
}

// sortedEcosystemNames renders ecosystem selectors in stable order, each
// prefixed with the supplied string (used for the "-" exclude marker).
func sortedEcosystemNames(ecosystems []sdk.Ecosystem, prefix string) []string {
	names := make([]string, 0, len(ecosystems))
	for _, ecosystem := range ecosystems {
		names = append(names, prefix+string(ecosystem))
	}
	sort.Strings(names)
	return names
}
