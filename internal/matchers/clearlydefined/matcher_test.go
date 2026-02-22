package clearlydefined

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

func TestCoordinateFromPackage(t *testing.T) {
	t.Run("composer package", func(t *testing.T) {
		coordinate, _, ok := coordinateFromPackage(&model.Package{
			Ecosystem: "php",
			Org:       "symfony",
			Name:      "console",
			Version:   "7.1.0",
		})
		if !ok {
			t.Fatal("expected composer package to map to ClearlyDefined coordinate")
		}
		if coordinate != "composer/packagist/symfony/console/7.1.0" {
			t.Fatalf("unexpected coordinate: %s", coordinate)
		}
	})

	t.Run("conda purl", func(t *testing.T) {
		coordinate, ok := coordinateFromParsedPURL(parsedPURL{
			Type:    "conda",
			Name:    "numpy",
			Version: "1.26.4-py310",
			Qualifiers: map[string]string{
				"channel": "conda-forge",
				"subdir":  "linux-64",
			},
		})
		if !ok {
			t.Fatal("expected conda purl to map to ClearlyDefined coordinate")
		}
		if coordinate != "conda/conda-forge/linux-64/numpy/1.26.4-py310" {
			t.Fatalf("unexpected coordinate: %s", coordinate)
		}
	})

	t.Run("unsupported ecosystem", func(t *testing.T) {
		if _, _, ok := coordinateFromPackage(&model.Package{
			Ecosystem: "npm",
			Name:      "react",
			Version:   "18.2.0",
		}); ok {
			t.Fatal("expected overlapping deps.dev ecosystem to be rejected")
		}
	})
}

func TestCheckerMatch_EnrichesMissingOnly(t *testing.T) {
	var stderr bytes.Buffer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/definitions/composer/packagist/symfony/console/7.1.0" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		response := response{}
		response.Licensed.Declared = "MIT"
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
	missing := model.NewPackage(model.Package{Ecosystem: "php", Org: "symfony", Name: "console", Version: "7.1.0"})
	existing := model.NewPackage(model.Package{
		Ecosystem: "php",
		Org:       "laravel",
		Name:      "framework",
		Version:   "11.0.0",
		Licenses:  []model.PackageLicense{{SPDXExpression: "MIT"}},
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
	if values := existing.LicenseValues(); len(values) != 1 || values[0] != "MIT" {
		t.Fatalf("expected existing package licenses to remain unchanged, got %#v", values)
	}
	logOutput := stderr.String()
	for _, want := range []string{
		"clearlydefined: license check summary",
		`"api_requests": 1`,
		`"api_enriched": 1`,
	} {
		if !strings.Contains(logOutput, want) {
			t.Fatalf("expected log output to contain %q, got:\n%s", want, logOutput)
		}
	}
	if strings.Contains(logOutput, "licenses applied from api") {
		t.Fatalf("expected aggregated logs, got:\n%s", logOutput)
	}
}
