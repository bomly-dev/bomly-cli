package engine

import "github.com/bomly-dev/bomly-cli/sdk"

// DeduplicateFindings removes duplicate package/vulnerability findings, keeping the highest-priority source.
func DeduplicateFindings(findings []sdk.Finding) []sdk.Finding {
	type key struct{ pkgID, vulnID string }
	type entry struct {
		idx  int
		rank int
	}
	best := make(map[key]entry, len(findings))
	out := make([]sdk.Finding, 0, len(findings))

	for _, finding := range findings {
		if finding.ID == "" || finding.Kind != sdk.FindingKindVulnerability {
			out = append(out, finding)
			continue
		}
		// Reference-style Finding: dedup by (PackageRef, VulnerabilityID).
		vulnID := finding.VulnerabilityID
		if vulnID == "" {
			vulnID = finding.ID
		}
		k := key{pkgID: finding.PackageRef, vulnID: vulnID}
		rank := findingSourceRank(finding.Source)
		if existing, ok := best[k]; !ok {
			best[k] = entry{idx: len(out), rank: rank}
			out = append(out, finding)
		} else if rank < existing.rank {
			out[existing.idx] = finding
			best[k] = entry{idx: existing.idx, rank: rank}
		}
	}
	return out
}

func findingSourceRank(source string) int {
	switch source {
	case "grype":
		return 0
	case "osv":
		return 1
	default:
		return 2
	}
}
