package syft

import "github.com/bomly/bomly-cli/internal/detectors"

var syftAuditEnrichmentValues = []string{"golang", "java", "javascript", "python"}

func syftCommandArgs(target string, req detectors.ResolveGraphRequest) []string {
	args := []string{target, "-o", "spdx-json"}
	if !req.EnrichmentEnabled {
		return args
	}

	for _, value := range syftAuditEnrichmentValues {
		args = append(args, "--enrich", value)
	}
	return args
}
