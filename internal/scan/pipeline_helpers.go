package scan

import (
	"strings"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

// unwrapJoinedErrors splits an error returned by errors.Join into its parts.
func unwrapJoinedErrors(err error) []error {
	if u, ok := err.(interface{ Unwrap() []error }); ok {
		return u.Unwrap()
	}
	return []error{err}
}

// PipelineWarningsFromError converts a (possibly joined) error into structured
// pipeline warnings. It extracts the source name from error messages that follow
// the pattern "<prefix> <name>: <message>" (e.g. "auditor osv: not ready").
func PipelineWarningsFromError(err error, prefix string) []PipelineWarning {
	if err == nil {
		return nil
	}
	var warnings []PipelineWarning
	for _, e := range unwrapJoinedErrors(err) {
		source, message := parseWarningSource(e.Error(), prefix)
		warnings = append(warnings, PipelineWarning{Source: source, Message: message})
	}
	return warnings
}

// parseWarningSource extracts a component name from error text formatted as
// "<prefix> <name>: <rest>" (e.g. "auditor grype: not ready"). If the text does
// not match the pattern, the full text is returned as the message with an empty source.
func parseWarningSource(text, prefix string) (source, message string) {
	p := prefix + " "
	if !strings.HasPrefix(text, p) {
		return "", text
	}
	rest := text[len(p):]
	idx := strings.Index(rest, ": ")
	if idx < 0 {
		return "", text
	}
	return rest[:idx], rest[idx+2:]
}

// filterResultsByScope applies scope filtering to each graph entry in the results.
func filterResultsByScope(results []model.DetectionResult, scope model.Scope) ([]model.DetectionResult, error) {
	if scope == model.ScopeUnknown {
		return results, nil
	}
	filtered := make([]model.DetectionResult, 0, len(results))
	for _, result := range results {
		if result.Graphs == nil {
			filtered = append(filtered, result)
			continue
		}
		entries := make([]model.GraphEntry, 0, len(result.Graphs.Entries))
		for _, entry := range result.Graphs.Entries {
			if entry.Graph == nil {
				entries = append(entries, entry)
				continue
			}
			graphView, err := FilterGraphByScope(entry.Graph, scope)
			if err != nil {
				return nil, err
			}
			entries = append(entries, model.GraphEntry{Graph: graphView, Manifest: entry.Manifest})
		}
		result.Graphs = &model.GraphContainer{Entries: entries}
		filtered = append(filtered, result)
	}
	return filtered, nil
}
