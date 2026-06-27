//go:build smoke

package smoke

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// Mock OSV server
// ---------------------------------------------------------------------------

// startMockOSV starts a local HTTP server that responds to OSV API querybatch
// requests with a deterministic empty-results response. For smoke tests we
// only need the audit pipeline to complete successfully — the exact
// vulnerability data is not the focus. Pre-recorded fixture responses can be
// added later for richer assertions.
func startMockOSV(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// The OSV client calls POST /v1/querybatch.
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read the request body to determine how many queries were sent.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var req struct {
			Queries []json.RawMessage `json:"queries"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		// Return an empty vulns array for each query.
		results := make([]map[string]any, len(req.Queries))
		for i := range results {
			results[i] = map[string]any{"vulns": []any{}}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})

	// The OSV client may also fetch individual vulnerabilities via
	// GET /v1/vulns/<ID>. Return a minimal response.
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "MOCK-0000",
			"summary": "mock vulnerability",
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// ---------------------------------------------------------------------------
// Enrichment and audit scan tests
// ---------------------------------------------------------------------------

func TestAuditScan(t *testing.T) {
	srv := startMockOSV(t)
	auditEnv := []string{"BOMLY_OSV_API_BASE=" + srv.URL}

	cases := []struct {
		name  string
		args  []string
		tools []string
	}{
		{
			name:  "scan-go-enrich",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-go-gomod", "--ref", "v1.0.0", "--format", "json", "--enrich", "--matchers", "osv"},
			tools: []string{"go"},
		},
		{
			name:  "scan-go-audit",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-go-gomod", "--ref", "v1.0.0", "--format", "json", "--enrich", "--audit", "--matchers", "osv", "--auditors", "vulnerability"},
			tools: []string{"go"},
		},
		{
			name:  "scan-go-audit-high",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-go-gomod", "--ref", "v1.0.0", "--format", "json", "--enrich", "--audit", "--fail-on", "high", "--matchers", "osv", "--auditors", "vulnerability"},
			tools: []string{"go"},
		},
		{
			name:  "scan-npm-audit",
			args:  []string{"scan", "--url", "https://github.com/bomly-dev/example-javascript-npm", "--ref", "v1.0.0", "--format", "json", "--enrich", "--audit", "--matchers", "osv", "--auditors", "vulnerability"},
			tools: []string{"npm"},
		},
	}

	for _, tc := range cases {
		tc := tc
		parallelSubtest(t, tc.name, func(t *testing.T) {
			for _, tool := range tc.tools {
				requireTool(t, tool)
			}

			stdout, stderr, code := runBomlyWithEnv(t, auditEnv, tc.args...)
			if code != 0 {
				t.Fatalf("bomly exited %d\nstderr:\n%s", code, stderr)
			}
			if len(stdout) == 0 {
				t.Fatal("bomly produced no stdout output")
			}

			got := normalizeJSON(t, []byte(stdout))
			assertGolden(t, tc.name, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Container audit scan tests
// ---------------------------------------------------------------------------

func TestContainerAuditScan(t *testing.T) {
	// requireContainerRuntime(t) — built-in Syft does not need docker/podman.

	srv := startMockOSV(t)
	auditEnv := []string{"BOMLY_OSV_API_BASE=" + srv.URL}

	cases := []struct {
		name string
		args []string
	}{
		{
			name: "container-scan-alpine-audit",
			args: []string{"scan", "--image", alpineImage, "--format", "json", "--enrich", "--audit", "--matchers", "osv", "--auditors", "vulnerability"},
		},
	}

	for _, tc := range cases {
		tc := tc
		parallelSubtest(t, tc.name, func(t *testing.T) {
			stdout, stderr, code := runBomlyWithEnv(t, auditEnv, tc.args...)
			if code != 0 {
				t.Fatalf("bomly exited %d\nstderr:\n%s", code, stderr)
			}
			if len(stdout) == 0 {
				t.Fatal("bomly produced no stdout output")
			}

			got := normalizeContainerJSON(t, []byte(stdout))
			assertGolden(t, tc.name, got)
		})
	}
}

func TestAuditDiffAndExplain(t *testing.T) {
	srv := startMockOSV(t)
	auditEnv := []string{"BOMLY_OSV_API_BASE=" + srv.URL}

	cases := []struct {
		name  string
		args  []string
		tools []string
	}{
		{
			name:  "diff-go-audit",
			args:  []string{"diff", "--url", "https://github.com/bomly-dev/example-go-gomod", "--base", "v0.9.0", "--head", "v1.0.0", "--format", "json", "--enrich", "--audit", "--matchers", "osv", "--auditors", "vulnerability"},
			tools: []string{"go"},
		},
		{
			name:  "explain-go-enrich",
			args:  []string{"explain", "golang.org/x/text", "--url", "https://github.com/bomly-dev/example-go-gomod", "--ref", "v1.0.0", "--format", "json", "--enrich", "--matchers", "osv"},
			tools: []string{"go"},
		},
	}

	for _, tc := range cases {
		tc := tc
		parallelSubtest(t, tc.name, func(t *testing.T) {
			for _, tool := range tc.tools {
				requireTool(t, tool)
			}

			stdout, stderr, code := runBomlyWithEnv(t, auditEnv, tc.args...)
			if code != 0 {
				t.Fatalf("bomly exited %d\nstderr:\n%s", code, stderr)
			}
			if len(stdout) == 0 {
				t.Fatal("bomly produced no stdout output")
			}

			got := normalizeJSON(t, []byte(stdout))
			assertGolden(t, tc.name, got)
		})
	}
}
