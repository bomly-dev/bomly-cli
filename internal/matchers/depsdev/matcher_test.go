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
	"github.com/bomly-dev/bomly-cli/internal/matchers/cache"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestVersionRequestFromPackage(t *testing.T) {
	t.Run("npm scoped package", func(t *testing.T) {
		req, _, ok := versionRequestFromPackage(&sdk.Package{Coordinates: sdk.Coordinates{Ecosystem: "npm",
			Org:     "@types",
			Name:    "node",
			Version: "20.12.0"},
		})
		if !ok {
			t.Fatal("expected npm package to map to deps.dev request")
		}
		if req.VersionKey.System != "NPM" || req.VersionKey.Name != "@types/node" {
			t.Fatalf("unexpected request: %#v", req)
		}
	})

	t.Run("maven from purl", func(t *testing.T) {
		req, _, ok := versionRequestFromPackage(&sdk.Package{Coordinates: sdk.Coordinates{PURL: "pkg:maven/org.slf4j/slf4j-api@2.0.13",
			Version: "2.0.13"},
		})
		if !ok {
			t.Fatal("expected maven purl to map to deps.dev request")
		}
		if req.VersionKey.System != "MAVEN" || req.VersionKey.Name != "org.slf4j:slf4j-api" {
			t.Fatalf("unexpected request: %#v", req)
		}
	})

	t.Run("go purl esbuild", func(t *testing.T) {
		req, _, ok := versionRequestFromPackage(&sdk.Package{Coordinates: sdk.Coordinates{PURL: "pkg:golang/github.com/evanw/esbuild@v0.28.0",
			Version: "v0.28.0"},
		})
		if !ok {
			t.Fatal("expected go purl to map to deps.dev request")
		}
		if req.VersionKey.System != "GO" || req.VersionKey.Name != "github.com/evanw/esbuild" || req.VersionKey.Version != "v0.28.0" {
			t.Fatalf("unexpected request: %#v", req)
		}
	})

	t.Run("go purl golang x module", func(t *testing.T) {
		req, _, ok := versionRequestFromPackage(&sdk.Package{Coordinates: sdk.Coordinates{PURL: "pkg:golang/golang.org/x/net@v0.55.0",
			Version: "v0.55.0"},
		})
		if !ok {
			t.Fatal("expected golang.org/x purl to map to deps.dev request")
		}
		if req.VersionKey.System != "GO" || req.VersionKey.Name != "golang.org/x/net" || req.VersionKey.Version != "v0.55.0" {
			t.Fatalf("unexpected request: %#v", req)
		}
	})

	t.Run("unsupported ecosystem", func(t *testing.T) {
		if _, _, ok := versionRequestFromPackage(&sdk.Package{Coordinates: sdk.Coordinates{Ecosystem: "conan",
			Name:    "openssl",
			Version: "1.1.1s"},
		}); ok {
			t.Fatal("expected unsupported ecosystem to be rejected")
		}
	})
}

func TestCheckerMatch_RefetchesCachedEmptyLicenseSet(t *testing.T) {
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
					LicenseDetails: []depsDevLicenseRef{{SPDX: "BSD-3-Clause", License: "BSD-3-Clause"}},
				},
			}},
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	fileCache, err := cache.NewFileCache(cacheDir, defaultCacheTTL)
	if err != nil {
		t.Fatalf("NewFileCache() error = %v", err)
	}
	pkg := &sdk.Package{Coordinates: sdk.Coordinates{PURL: "pkg:golang/golang.org/x/net@v0.55.0", Version: "v0.55.0"}}
	_, cacheKey, ok := versionRequestFromPackage(pkg)
	if !ok {
		t.Fatal("expected package to produce cache key")
	}
	if err := cache.Set(fileCache, cacheKey, []string{}); err != nil {
		t.Fatalf("seed empty cache entry: %v", err)
	}

	checker, err := New(Config{
		APIBase:  server.URL,
		CacheDir: cacheDir,
		Client:   server.Client(),
		Logger:   logging.NewConsole(&stderr, 2, false),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	g := sdk.New()
	dep := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemGo, Name: "golang.org/x/net", Version: "v0.55.0"}})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	registry := sdk.NewPackageRegistry()

	result, err := checker.Match(context.Background(), sdk.MatchRequest{Graph: g, Registry: registry})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	gotPkg, _ := result.Registry.Get("pkg:golang/golang.org/x/net@v0.55.0")
	if gotPkg == nil || len(gotPkg.LicenseValues()) != 1 || gotPkg.LicenseValues()[0] != "BSD-3-Clause" {
		t.Fatalf("expected API license after empty cache refetch, got %#v", gotPkg)
	}
	if hits != 1 {
		t.Fatalf("expected one API hit after cached empty value, got %d", hits)
	}
	logOutput := stderr.String()
	for _, want := range []string{`"cache_hits": 1`, `"cache_empty": 1`, `"api_enriched": 1`} {
		if !strings.Contains(logOutput, want) {
			t.Fatalf("expected log output to contain %q, got:\n%s", want, logOutput)
		}
	}
}

func TestCheckerMatch_DoesNotCacheEmptyAPIResponse(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if err := json.NewEncoder(w).Encode(versionBatchResponse{
			Responses: []versionBatchResult{{Version: depsDevVersion{}}},
		}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	checker, err := New(Config{
		APIBase:  server.URL,
		CacheDir: t.TempDir(),
		Client:   server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for i := 0; i < 2; i++ {
		g := sdk.New()
		dep := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemGo, Name: "golang.org/x/net", Version: "v0.55.0"}})
		if err := g.AddNode(dep); err != nil {
			t.Fatalf("add dependency: %v", err)
		}
		if _, err := checker.Match(context.Background(), sdk.MatchRequest{Graph: g, Registry: sdk.NewPackageRegistry()}); err != nil {
			t.Fatalf("Match() run %d error = %v", i+1, err)
		}
	}
	if hits != 2 {
		t.Fatalf("expected empty API response not to be cached; hits = %d, want 2", hits)
	}
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

	g := sdk.New()
	missing := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "react", Version: "18.2.0"}})
	existing := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "zod", Version: "3.23.0"}})
	if err := g.AddNode(missing); err != nil {
		t.Fatalf("add missing dependency: %v", err)
	}
	if err := g.AddNode(existing); err != nil {
		t.Fatalf("add existing dependency: %v", err)
	}

	registry := sdk.NewPackageRegistry()
	existingPURL := sdk.CanonicalPackageURLFromDependency(existing)
	registry.Ensure(existingPURL).Licenses = []sdk.PackageLicense{{SPDXExpression: "Apache-2.0"}}

	result, err := checker.Match(context.Background(), sdk.MatchRequest{
		Graph:    g,
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if result.Registry != registry {
		t.Fatalf("expected registry to be enriched in place")
	}
	missingPkg, _ := result.Registry.Get(sdk.CanonicalPackageURLFromDependency(missing))
	if missingPkg == nil || len(missingPkg.LicenseValues()) != 1 || missingPkg.LicenseValues()[0] != "MIT" {
		t.Fatalf("expected missing package licenses to be enriched, got %#v", missingPkg)
	}
	existingPkg, _ := result.Registry.Get(existingPURL)
	if existingPkg == nil || len(existingPkg.LicenseValues()) != 1 || existingPkg.LicenseValues()[0] != "Apache-2.0" {
		t.Fatalf("expected existing package licenses to remain unchanged, got %#v", existingPkg)
	}
	if hits != 1 {
		t.Fatalf("expected one deps.dev batch request, got %d", hits)
	}
	logOutput := stderr.String()
	for _, want := range []string{
		"deps.dev: license matcher summary",
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
