package syft

import (
	"github.com/bomly-dev/bomly-cli/sdk"
)

var syftDetectorEnrichmentValues = []string{"golang", "java", "javascript", "python"}

func syftCommandArgs(target string, req sdk.DetectionRequest) []string {
	args := []string{target, "-o", "spdx-json"}
	args = append(args, syftCatalogerSelectionArgs(req)...)
	if !req.EnrichmentEnabled {
		return args
	}

	for _, value := range syftDetectorEnrichmentValues {
		args = append(args, "--enrich", value)
	}
	return args
}
