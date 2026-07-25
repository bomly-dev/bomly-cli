package opts

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// discoveryReadinessTimeout bounds the readiness probes the diagnostics run
// for a candidate whose detector chain survived every filter. Readiness checks
// shell out (PATH lookups, `java -version`), and this runs only on the
// "no subprojects discovered" failure path, so a short cap keeps a broken
// toolchain from stalling the error message.
const discoveryReadinessTimeout = 5 * time.Second

// discoveryDiagnostics explains, per probed manifest candidate, why discovery
// did not turn it into a subproject. It replays the same applicability checks
// planning performed — recursion scope, depth cap, exclude globs, ecosystem
// and detector filters, detector registration — and, when a candidate clears
// all of them, probes the planned detector chain for readiness so an
// unusable toolchain is named instead of silently producing nothing.
//
// A nil *discoveryDiagnostics is valid and reports no reasons; the exported
// DescribeDiscovery probe has no request context to replay.
type discoveryDiagnostics struct {
	req       Request
	planning  *engine.Registry
	excludes  []string
	ctx       context.Context
	cancelCtx context.CancelFunc
}

// newDiscoveryDiagnostics binds the planning registry (already narrowed by the
// active filters) and the request that produced the failure.
func newDiscoveryDiagnostics(registryValue *engine.Registry, req Request) *discoveryDiagnostics {
	ctx, cancel := context.WithTimeout(context.Background(), discoveryReadinessTimeout)
	return &discoveryDiagnostics{
		req:       req,
		planning:  registryValue,
		excludes:  normalizeExcludeGlobs(req.ExcludeGlobs),
		ctx:       ctx,
		cancelCtx: cancel,
	}
}

// close releases the readiness probe context.
func (d *discoveryDiagnostics) close() {
	if d == nil || d.cancelCtx == nil {
		return
	}
	d.cancelCtx()
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
	subproject, reason := d.detectorSkipReason(dir, manager)
	if reason != "" {
		return reason
	}
	return d.readinessSkipReason(subproject, manager)
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

// detectorSkipReason reports candidates with no registered detector or with
// every candidate detector filtered out. When the candidate survives both, it
// returns the subproject planning would have produced so the caller can carry
// on with the checks that run after planning.
func (d *discoveryDiagnostics) detectorSkipReason(dir string, manager sdk.PackageManager) (sdk.Subproject, string) {
	if d.planning == nil {
		return sdk.Subproject{}, ""
	}

	registryValue := d.req.Registry
	if registryValue == nil {
		registryValue = d.planning
	}
	candidates := detectorNamesForPackageManager(registryValue, d.req.ExecutionTarget.Kind, dir, manager)
	if len(candidates) == 0 {
		return sdk.Subproject{}, fmt.Sprintf("no detector registered for %s", manager.Name())
	}

	chain := expandDetectorNames(d.planning, d.planning.PlannedDetectors(sdk.DetectionRequest{
		ProjectPath:     dir,
		ExecutionTarget: d.req.ExecutionTarget,
		Ecosystem:       manager.Ecosystem(),
		PackageManager:  manager,
		DetectorFilter:  d.req.DetectorFilter,
	}, candidates))
	if len(chain) == 0 {
		return sdk.Subproject{}, fmt.Sprintf("detector filter excludes every %s detector (%s)", manager.Name(), strings.Join(candidates, ", "))
	}

	subproject, ok := plannedSubprojectForPackageManager(
		d.planning,
		d.req.ExecutionTarget,
		dir,
		manager,
		nil,
		d.req.DetectorFilter,
	)
	if !ok {
		return sdk.Subproject{}, fmt.Sprintf("no resolvable %s manifest in this directory", manager.Name())
	}
	return subproject, ""
}

// readinessSkipReason probes the planned detector chain and reports the
// readiness failures when no link in the chain can run. A chain with at least
// one ready detector yields "" — the candidate is usable, and something other
// than this candidate explains the empty discovery.
func (d *discoveryDiagnostics) readinessSkipReason(subproject sdk.Subproject, manager sdk.PackageManager) string {
	// An empty chain must not fall through to PlannedDetectors' "no names
	// means every detector" behavior: there is nothing to probe.
	if d.planning == nil || len(subproject.PlannedDetectors) == 0 {
		return ""
	}

	req := sdk.DetectionRequest{
		ProjectPath:     subproject.ExecutionTarget.Location,
		ExecutionTarget: subproject.ExecutionTarget,
		Subproject:      subproject,
		Ecosystem:       subproject.Ecosystem,
		PackageManager:  manager,
		DetectorFilter:  d.req.DetectorFilter,
	}

	detectorList := d.planning.PlannedDetectors(req, subproject.PlannedDetectors)
	if len(detectorList) == 0 {
		return ""
	}

	failures := make([]string, 0, len(detectorList))
	for _, detector := range detectorList {
		if detector == nil {
			continue
		}
		if err := detector.Ready(d.ctx, req); err != nil {
			failures = append(failures, fmt.Sprintf("%s not ready (%v)", detector.Descriptor().Name, err))
			continue
		}
		// At least one detector in the chain can run.
		return ""
	}
	if len(failures) == 0 {
		return ""
	}
	return strings.Join(failures, "; ")
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
