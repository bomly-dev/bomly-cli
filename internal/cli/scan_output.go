package cli

import (
	enginediff "github.com/bomly-dev/bomly-cli/internal/engine/diff"
	"github.com/bomly-dev/bomly-cli/internal/output"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

func diffAuditOutput(audit *enginediff.Audit) *output.DiffAudit {
	if audit == nil {
		return nil
	}
	combined := append(append([]model.Finding{}, audit.Introduced...), audit.Persisted...)
	combined = append(combined, audit.Resolved...)
	return &output.DiffAudit{
		Introduced:   output.FindingsFromScan(audit.Introduced),
		Resolved:     output.FindingsFromScan(audit.Resolved),
		Persisted:    output.FindingsFromScan(audit.Persisted),
		AuditSummary: output.SummaryFromFindings(combined),
	}
}

func explainPackageRef(pkg *model.Package) output.PackageRef {
	ref := output.PackageFromGraphPackage(pkg)
	if pkg == nil {
		return ref
	}
	if legacyID := pkg.StableID(); legacyID != "" {
		ref.ID = legacyID
	}
	return ref
}

func explainPathsWithStableIDs(paths []output.DependencyPath) []output.DependencyPath {
	out := make([]output.DependencyPath, len(paths))
	for i, path := range paths {
		out[i] = path
		out[i].Packages = make([]output.PackageRef, len(path.Packages))
		for j, ref := range path.Packages {
			out[i].Packages[j] = explainPackageRefFromOutput(ref)
		}
		if len(out[i].Packages) > 0 {
			out[i].IntroducedVia = out[i].Packages[0].ID
		}
		if path.CycleTo != "" {
			for _, ref := range out[i].Packages {
				if ref.Purl == path.CycleTo || ref.ID == path.CycleTo {
					out[i].CycleTo = ref.ID
					break
				}
			}
		}
	}
	return out
}

func explainPackageRefFromOutput(ref output.PackageRef) output.PackageRef {
	if ref.Name != "" && ref.Version != "" {
		ref.ID = ref.Name + "@" + ref.Version
	}
	return ref
}
