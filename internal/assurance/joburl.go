package assurance

import (
	"encoding/json"
	"fmt"
)

// maxJobsPayloadBytes bounds the workflow-jobs response this package parses.
const maxJobsPayloadBytes = 8 << 20

type jobsPayload struct {
	Jobs []struct {
		Name       string `json:"name"`
		Status     string `json:"status"`
		RunnerName string `json:"runner_name"`
		HTMLURL    string `json:"html_url"`
	} `json:"jobs"`
}

// MatchJobURL picks the URL of the job a check is running inside, so a reported
// count links to the exact log that produced it rather than to the whole run.
//
// A runner executes one job at a time, so the running job on this runner is the
// caller's own job — that holds for matrix legs and for jobs contributed by a
// called workflow, which is why the runner name is matched rather than the job
// name (display names differ between direct and nested invocations). Returns an
// empty string when there is no confident match; callers fall back to the run.
func MatchJobURL(payload []byte, runnerName string) (string, error) {
	if len(payload) > maxJobsPayloadBytes {
		return "", fmt.Errorf("workflow jobs payload is %d bytes, limit is %d", len(payload), maxJobsPayloadBytes)
	}
	if runnerName == "" {
		return "", nil
	}
	var jobs jobsPayload
	if err := json.Unmarshal(payload, &jobs); err != nil {
		return "", fmt.Errorf("decode workflow jobs: %w", err)
	}
	match := ""
	for _, job := range jobs.Jobs {
		if job.RunnerName != runnerName || job.Status != "in_progress" || job.HTMLURL == "" {
			continue
		}
		if match != "" {
			// Two running jobs claiming the same runner should not happen; if
			// it does, a wrong link is worse than the run-level one.
			return "", nil
		}
		match = job.HTMLURL
	}
	return match, nil
}
