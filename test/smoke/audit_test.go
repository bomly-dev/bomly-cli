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
// Audit scan tests
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
			name:  "scan-go-audit",
			args:  []string{"scan", "--url", "https://github.com/google/uuid", "--ref", "v1.6.0", "--format", "json", "--audit", "--auditors", "osv"},
			tools: []string{"go"},
		},
		{
			name:  "scan-npm-audit",
			args:  []string{"scan", "--url", "https://github.com/ljharb/qs", "--ref", "v6.13.0", "--format", "json", "--audit", "--auditors", "osv"},
			tools: []string{"npm"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
			args: []string{"scan", "--container", alpineImage, "--format", "json", "--audit", "--auditors", "osv"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
