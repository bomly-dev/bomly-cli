package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/logging"
	audcache "github.com/bomly-dev/bomly-cli/internal/matchers/cache"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// --- buildQuery ---

func TestBuildQuery_PURLBased(t *testing.T) {
	dep := &sdk.Dependency{Coordinates: sdk.Coordinates{Name: "lodash",
		Version:   "4.17.15",
		PURL:      "pkg:npm/lodash@4.17.15",
		Ecosystem: "npm"},
	}
	purl := sdk.CanonicalPackageURLFromDependency(dep)
	key, query, ok := buildQuery(dep, purl)
	if !ok {
		t.Fatal("expected query to be built for PURL package")
	}
	if key == (audcache.Key{}) {
		t.Error("expected non-zero cache key")
	}
	if query.Version != "" {
		t.Errorf("PURL query should not set Version; got %q", query.Version)
	}
	var purlPkg PurlPackage
	if err := json.Unmarshal(query.Package, &purlPkg); err != nil {
		t.Fatalf("expected PurlPackage JSON: %v", err)
	}
	if purlPkg.Purl != "pkg:npm/lodash@4.17.15" {
		t.Errorf("PURL = %q, want %q", purlPkg.Purl, "pkg:npm/lodash@4.17.15")
	}
}

func TestBuildQuery_NameEcosystemVersion(t *testing.T) {
	dep := &sdk.Dependency{Coordinates: sdk.Coordinates{Name: "requests",
		Version:   "2.28.0",
		Ecosystem: "python"},
	}
	// Force the name+ecosystem fallback by passing an empty PURL.
	key, query, ok := buildQuery(dep, "")
	if !ok {
		t.Fatal("expected query to be built for name+ecosystem package")
	}
	if key == (audcache.Key{}) {
		t.Error("expected non-zero cache key")
	}
	if query.Version != "2.28.0" {
		t.Errorf("Version = %q, want %q", query.Version, "2.28.0")
	}
	var namePkg NamePackage
	if err := json.Unmarshal(query.Package, &namePkg); err != nil {
		t.Fatalf("expected NamePackage JSON: %v", err)
	}
	if namePkg.Name != "requests" {
		t.Errorf("Name = %q, want %q", namePkg.Name, "requests")
	}
	if namePkg.Ecosystem != "PyPI" {
		t.Errorf("Ecosystem = %q, want %q", namePkg.Ecosystem, "PyPI")
	}
}

func TestBuildQuery_SkipsNoVersion(t *testing.T) {
	dep := &sdk.Dependency{Coordinates: sdk.Coordinates{Name: "lodash", Ecosystem: "npm"}}
	_, _, ok := buildQuery(dep, "")
	if ok {
		t.Error("expected package without version to be skipped (no query built)")
	}
}

func TestBuildQuery_SkipsUnknownEcosystem(t *testing.T) {
	dep := &sdk.Dependency{Coordinates: sdk.Coordinates{Name: "my-pkg", Version: "1.0.0", Ecosystem: "unknown-eco"}}
	_, _, ok := buildQuery(dep, "")
	if ok {
		t.Error("expected package with unknown ecosystem and no PURL to be skipped")
	}
}

// --- enrichment ---

func buildTestGraph() *sdk.Graph {
	graph := sdk.New()
	dep := sdk.NewDependencyRef("vulnerable-pkg", "1.0.0")
	dep.PURL = "pkg:generic/vulnerable-pkg@1.0.0"
	_ = graph.AddNode(dep)
	return graph
}

func TestMatcherMatchEnrichesRegistry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			_ = json.NewEncoder(w).Encode(BatchResponse{Results: []BatchResult{{Vulns: []VulnRef{{ID: "OSV-2024-0001"}}}}})
		case "/v1/vulns/OSV-2024-0001":
			_ = json.NewEncoder(w).Encode(Vulnerability{ID: "OSV-2024-0001", Summary: "Test vuln"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	matcher, err := New(Config{APIBase: server.URL, CacheDir: t.TempDir(), EnableKEV: false})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	registry := sdk.NewPackageRegistry()
	result, err := matcher.Match(context.Background(), sdk.MatchRequest{
		Graph:    buildTestGraph(),
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}

	var vulns []sdk.Vulnerability
	for _, pkg := range result.Registry.All() {
		vulns = append(vulns, pkg.Vulnerabilities...)
	}
	if len(vulns) == 0 {
		t.Fatal("expected vulnerabilities to be attached to the registry")
	}
	if vulns[0].Source != "osv" || vulns[0].ID != "OSV-2024-0001" {
		t.Fatalf("unexpected vulnerability: %#v", vulns[0])
	}
}

// --- cache hit ---

func TestAudit_CacheHit_NoHTTPCall(t *testing.T) {
	calls := 0
	var stderr bytes.Buffer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer srv.Close()

	aud, err := New(Config{
		APIBase:   srv.URL,
		CacheDir:  t.TempDir(),
		CacheTTL:  time.Hour,
		EnableKEV: false,
		Logger:    logging.NewConsole(&stderr, 2, false),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	dep := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Name: "lodash",
		Version:   "4.17.15",
		PURL:      "pkg:npm/lodash@4.17.15",
		Ecosystem: "npm"},
	})
	purl := sdk.CanonicalPackageURLFromDependency(dep)

	// Pre-populate cache so the matcher won't need to call the server.
	key := audcache.NewKey(purl, "", "", "")
	cached := []Vulnerability{{ID: "CVE-2020-1234", Summary: "test vuln"}}
	_ = audcache.Set(aud.cache, key, cached)

	g := sdk.New()
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	registry := sdk.NewPackageRegistry()
	result, err := aud.Match(context.Background(), sdk.MatchRequest{
		Graph:    g,
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}

	if calls != 0 {
		t.Errorf("expected 0 HTTP calls (cache hit), got %d", calls)
	}
	foundVuln := false
	for _, pkg := range result.Registry.All() {
		for _, vulnerability := range pkg.Vulnerabilities {
			if vulnerability.ID == "CVE-2020-1234" {
				foundVuln = true
			}
		}
	}
	if !foundVuln {
		t.Error("expected cached vulnerability CVE-2020-1234 to appear in registry enrichment")
	}
	logOutput := stderr.String()
	for _, want := range []string{
		"OSV enriching 1 packages with vulnerability data",
		"osv: package cache summary",
		`"cache_hits": 1`,
		`"cache_misses": 0`,
		`"cached_findings": 1`,
	} {
		if !strings.Contains(logOutput, want) {
			t.Fatalf("expected log output to contain %q, got:\n%s", want, logOutput)
		}
	}
}

// --- OSV API failure ---

func TestAudit_OSVFailure_NonFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	aud, err := New(Config{
		APIBase:   srv.URL,
		CacheDir:  t.TempDir(),
		CacheTTL:  time.Hour,
		EnableKEV: false,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	dep := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Name: "lodash",
		Version:   "4.17.15",
		PURL:      "pkg:npm/lodash@4.17.15",
		Ecosystem: "npm"},
	})
	g := sdk.New()
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	result, err := aud.Match(context.Background(), sdk.MatchRequest{
		Graph:    g,
		Registry: sdk.NewPackageRegistry(),
	})
	if err != nil {
		t.Fatalf("Match returned error on API failure (should be non-fatal): %v", err)
	}
	_ = result // partial results are acceptable
}

// --- KEV enrichment ---

func TestMarkKEVVulnerabilities_AppendsReason(t *testing.T) {
	catalog := &KEVCatalog{ids: map[string]struct{}{"CVE-2021-44228": {}}}

	vulns := map[string][]sdk.Vulnerability{
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": {
			{ID: "CVE-2021-44228", Source: "osv", Reasons: []string{"existing reason"}},
			{ID: "CVE-2099-9999", Source: "osv"},
		},
	}
	marked := markKEVVulnerabilities(vulns, catalog)

	want := map[string]bool{"CVE-2021-44228": true, "CVE-2099-9999": false}
	for _, list := range marked {
		for _, v := range list {
			kevFound := false
			for _, r := range v.Reasons {
				if strings.HasPrefix(r, "CISA KEV:") {
					kevFound = true
					break
				}
			}
			if kevFound != want[v.ID] {
				t.Errorf("vuln %q: KEV reason present = %v, want %v (reasons: %v)", v.ID, kevFound, want[v.ID], v.Reasons)
			}
			if v.ID == "CVE-2021-44228" && !v.KEVExploited {
				t.Errorf("expected CVE-2021-44228 KEVExploited=true")
			}
		}
	}
}

// --- severity extraction ---

func TestCvssScoreToBand(t *testing.T) {
	tests := []struct {
		score float64
		want  sdk.SeverityLevel
	}{
		{9.0, "critical"},
		{9.5, "critical"},
		{10.0, sdk.SeverityCritical},
		{7.0, sdk.SeverityHigh},
		{8.9, sdk.SeverityHigh},
		{4.0, sdk.SeverityMedium},
		{6.9, sdk.SeverityMedium},
		{0.1, sdk.SeverityLow},
		{3.9, sdk.SeverityLow},
		{0.0, sdk.SeverityLow},
	}
	for _, tt := range tests {
		got := cvssScoreToBand(tt.score)
		if got != tt.want {
			t.Errorf("cvssScoreToBand(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestParseCVSSScore(t *testing.T) {
	tests := []struct {
		name string
		kind string
		raw  string
		want float64
	}{
		{name: "numeric score", kind: "CVSS_V3", raw: "7.5", want: 7.5},
		{name: "vector with explicit prefix", kind: "CVSS_V3", raw: "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L", want: 2.5},
		{name: "vector inferred from severity type", kind: "CVSS_V31", raw: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", want: 9.8},
		{name: "v2 vector", kind: "CVSS_V2", raw: "AV:N/AC:L/Au:N/C:P/I:P/A:P", want: 7.5},
		{name: "v4 vector inferred from severity type", kind: "CVSS_V4", raw: "AV:L/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N", want: 2.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCVSSScore(tt.kind, tt.raw)
			if got != tt.want {
				t.Fatalf("parseCVSSScore(%q, %q) = %v, want %v", tt.kind, tt.raw, got, tt.want)
			}
		})
	}
}

func TestExtractSeverity_CalculatesFromVector(t *testing.T) {
	got := extractSeverity([]Severity{{
		Type:  "CVSS_V3",
		Score: "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L",
	}})

	if got != "low" {
		t.Fatalf("extractSeverity() = %q, want %q", got, "low")
	}
}

func TestExtractSeverity_PrefersHigherVersion(t *testing.T) {
	got := extractSeverity([]Severity{
		{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{Type: "CVSS_V4", Score: "AV:L/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N"},
	})

	if got != "low" {
		t.Fatalf("extractSeverity() = %q, want %q", got, "low")
	}
}
