package depsdev

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/logging"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestVersionRequestFromPackage(t *testing.T) {
	t.Run("npm scoped package", func(t *testing.T) {
		req, _, ok := versionRequestFromPackage(&model.Package{
			Ecosystem: "npm",
			Org:       "@types",
			Name:      "node",
			Version:   "20.12.0",
		})
		if !ok {
			t.Fatal("expected npm package to map to deps.dev request")
		}
		if req.VersionKey.System != "NPM" || req.VersionKey.Name != "@types/node" {
			t.Fatalf("unexpected request: %#v", req)
		}
	})

	t.Run("maven from purl", func(t *testing.T) {
		req, _, ok := versionRequestFromPackage(&model.Package{
			PURL:    "pkg:maven/org.slf4j/slf4j-api@2.0.13",
			Version: "2.0.13",
		})
		if !ok {
			t.Fatal("expected maven purl to map to deps.dev request")
		}
		if req.VersionKey.System != "MAVEN" || req.VersionKey.Name != "org.slf4j:slf4j-api" {
			t.Fatalf("unexpected request: %#v", req)
		}
	})

	t.Run("unsupported ecosystem", func(t *testing.T) {
		if _, _, ok := versionRequestFromPackage(&model.Package{
			Ecosystem: "php",
			Name:      "symfony/console",
			Version:   "7.1.0",
		}); ok {
			t.Fatal("expected unsupported ecosystem to be rejected")
		}
	})
}

func TestCheckerMatch_EnrichesMissingOnly(t *testing.T) {
	var hits int
	var stderr bytes.Buffer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodPost || r.URL.Path != "/versionbatch" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		response := versionBatchResponse{
			Responses: []versionBatchResult{{
				Version: depsDevVersion{
					LicenseDetails: []depsDevLicenseRef{{SPDX: "MIT", License: "MIT"}},
				},
			}},
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	checker, err := New(Config{
		APIBase:  server.URL,
		CacheDir: t.TempDir(),
		Client:   server.Client(),
		Logger:   logging.NewConsole(&stderr, 2, false),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	g := model.New()
	missing := model.NewPackage(model.Package{Ecosystem: "npm", Name: "react", Version: "18.2.0"})
	existing := model.NewPackage(model.Package{
		Ecosystem: "npm",
		Name:      "zod",
		Version:   "3.23.0",
		Licenses:  []model.PackageLicense{{SPDXExpression: "Apache-2.0"}},
	})
	if err := g.AddPackage(missing); err != nil {
		t.Fatalf("add missing package: %v", err)
	}
	if err := g.AddPackage(existing); err != nil {
		t.Fatalf("add existing package: %v", err)
	}

	result, err := checker.Match(context.Background(), model.MatchRequest{
		Mode:  model.TargetModeFullGraph,
		Graph: g,
	})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if result.Graph != g {
		t.Fatalf("expected graph to be enriched in place")
	}
	if values := missing.LicenseValues(); len(values) != 1 || values[0] != "MIT" {
		t.Fatalf("expected missing package licenses to be enriched, got %#v", values)
	}
	if values := existing.LicenseValues(); len(values) != 1 || values[0] != "Apache-2.0" {
		t.Fatalf("expected existing package licenses to remain unchanged, got %#v", values)
	}
	if hits != 1 {
		t.Fatalf("expected one deps.dev batch request, got %d", hits)
	}
	logOutput := stderr.String()
	for _, want := range []string{
		"deps.dev: license check summary",
		`"cache_hits": 0`,
		`"cache_misses": 1`,
		`"api_requests": 1`,
		`"api_enriched": 1`,
	} {
		if !strings.Contains(logOutput, want) {
			t.Fatalf("expected log output to contain %q, got:\n%s", want, logOutput)
		}
	}
	for _, unwanted := range []string{
		"raw batch response body",
		"fetching license batch",
		"batch result summary",
		"cache hit",
		"cache miss",
		"licenses applied from api",
	} {
		if strings.Contains(logOutput, unwanted) {
			t.Fatalf("expected log output to omit %q, got:\n%s", unwanted, logOutput)
		}
	}
}
