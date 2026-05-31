package eol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestMatchEnrichesPackageMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/all.json":
			_ = json.NewEncoder(w).Encode([]string{"django"})
		case "/api/django.json":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"cycle":   "4.2",
				"eol":     "2030-01-01",
				"support": false,
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	checker, err := New(Config{
		APIBase:  server.URL + "/api",
		CacheDir: t.TempDir(),
		CacheTTL: time.Hour,
		Client:   server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	g := sdk.New()
	dep := sdk.NewDependency(sdk.Dependency{Ecosystem: "python", Name: "django", Version: "4.2.9"})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}

	registry := sdk.NewPackageRegistry()
	_, err = checker.Match(context.Background(), sdk.MatchRequest{Graph: g, Registry: registry, Mode: sdk.TargetModeFullGraph})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}

	pkg, ok := registry.Get(sdk.CanonicalPackageURLFromDependency(dep))
	if !ok {
		t.Fatalf("expected registry package for django")
	}
	got, ok := pkg.Metadata[metadataEOLKey].(map[string]any)
	if !ok {
		t.Fatalf("expected eol metadata map, got %#v", pkg.Metadata[metadataEOLKey])
	}
	if got["status"] != statusSupported {
		t.Fatalf("expected status %q, got %#v", statusSupported, got["status"])
	}
	if got["cycle"] != "4.2" {
		t.Fatalf("expected cycle 4.2, got %#v", got["cycle"])
	}
}

func TestFetchProductsUsesCacheAfterFirstRequest(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		_ = json.NewEncoder(w).Encode([]string{"django"})
	}))
	defer server.Close()

	cacheDir := filepath.Join(t.TempDir(), "cache")
	checker, err := New(Config{
		APIBase:  server.URL,
		CacheDir: cacheDir,
		CacheTTL: time.Hour,
		Client:   server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := checker.fetchProducts(context.Background()); err != nil {
		t.Fatalf("fetchProducts() error = %v", err)
	}
	if _, err := checker.fetchProducts(context.Background()); err != nil {
		t.Fatalf("fetchProducts() second call error = %v", err)
	}
	if requestCount != 1 {
		t.Fatalf("expected one HTTP request due to cache, got %d", requestCount)
	}
}

func TestMatchCycleFallback(t *testing.T) {
	cycles := []productCycle{{Cycle: "1", EOL: dateOrBool{Date: "2030-01-01"}}}
	matched, ok := matchCycle("1.2.3", cycles)
	if !ok {
		t.Fatal("expected cycle match")
	}
	if matched.Cycle != "1" {
		t.Fatalf("expected cycle 1, got %q", matched.Cycle)
	}
}
