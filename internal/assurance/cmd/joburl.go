package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/assurance"
)

// jobURL returns the URL a check result should point at: the job it ran in when
// that can be resolved, and the workflow run otherwise.
//
// Every instance of a matrix check shares one run, so run-level links cannot
// tell a reader which platform or slice a number came from. Resolving the job
// costs one read of public workflow metadata and is skipped silently whenever
// it does not work.
func jobURL(runURL string) string {
	if override := os.Getenv("ASSURANCE_JOB_URL"); override != "" {
		return override
	}
	repository := os.Getenv("GITHUB_REPOSITORY")
	runID := os.Getenv("GITHUB_RUN_ID")
	runnerName := os.Getenv("RUNNER_NAME")
	if repository == "" || runID == "" || runnerName == "" {
		return runURL
	}
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/actions/runs/%s/jobs?per_page=100", repository, runID)
	if attempt := os.Getenv("GITHUB_RUN_ATTEMPT"); attempt != "" {
		endpoint = fmt.Sprintf("https://api.github.com/repos/%s/actions/runs/%s/attempts/%s/jobs?per_page=100",
			repository, runID, attempt)
	}
	payload, err := fetchJSON(endpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "assurance: could not resolve the job URL (%v); linking the run instead\n", err)
		return runURL
	}
	resolved, err := assurance.MatchJobURL(payload, runnerName)
	if err != nil || resolved == "" {
		return runURL
	}
	return resolved
}

func fetchJSON(endpoint string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	// The token lifts the rate limit; the endpoint is readable without one on a
	// public repository, so a missing token is not an error.
	for _, name := range []string{"GH_TOKEN", "GITHUB_TOKEN"} {
		if token := os.Getenv(name); token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
			break
		}
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("workflow jobs request returned %s", response.Status)
	}
	return io.ReadAll(io.LimitReader(response.Body, 8<<20))
}
