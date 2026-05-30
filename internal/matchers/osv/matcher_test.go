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
	pkg := &sdk.Package{
		Name:      "lodash",
		Version:   "4.17.15",
		PURL:      "pkg:npm/lodash@4.17.15",
		Ecosystem: "npm",
	}
	key, query, ok := buildQuery(pkg)
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
	pkg := &sdk.Package{
		Name:      "requests",
		Version:   "2.28.0",
		PURL:      "",
		Ecosystem: "python",
	}
	key, query, ok := buildQuery(pkg)
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
	pkg := &sdk.Package{Name: "lodash", PURL: "", Ecosystem: "npm"}
	_, _, ok := buildQuery(pkg)
	if ok {
		t.Error("expected package without version to be skipped (no query built)")
	}
}

func TestBuildQuery_SkipsUnknownEcosystem(t *testing.T) {
	pkg := &sdk.Package{Name: "my-pkg", Version: "1.0.0", PURL: "", Ecosystem: "unknown-eco"}
	_, _, ok := buildQuery(pkg)
	if ok {
		t.Error("expected package with unknown ecosystem and no PURL to be skipped")
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

	cacheDir := t.TempDir()
	aud, err := New(Config{
		APIBase:   srv.URL,
		CacheDir:  cacheDir,
		CacheTTL:  time.Hour,
		EnableKEV: false,
		Logger:    logging.NewConsole(&stderr, 2, false),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pkg := &sdk.Package{
		ID:        "npm:lodash:4.17.15",
		Name:      "lodash",
		Version:   "4.17.15",
		PURL:      "pkg:npm/lodash@4.17.15",
		Ecosystem: "npm",
		Licenses:  []sdk.PackageLicense{{Value: "MIT"}},
	}

	// Pre-populate cache so the auditor won't need to call the server.
	key := audcache.NewKey(pkg.PURL, "", "", "")
	cached := []OsvVulnerability{{ID: "CVE-2020-1234", Summary: "test vuln"}}
	_ = audcache.Set(aud.cache, key, cached)

	g := sdk.New()
	if err := g.AddNode(pkg); err != nil {
		t.Fatalf("AddPackage: %v", err)
	}

	req := sdk.MatchRequest{
		Graph: g,
		Mode:  sdk.TargetModeFullGraph,
	}
	result, err := aud.Match(context.Background(), req)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}

	if calls != 0 {
		t.Errorf("expected 0 HTTP calls (cache hit), got %d", calls)
	}
	foundVuln := false
	for _, enrichedPkg := range result.Graph.Nodes() {
		for _, vulnerability := range enrichedPkg.Vulnerabilities {
			if vulnerability.ID == "CVE-2020-1234" {
				foundVuln = true
			}
		}
	}
	if !foundVuln {
		t.Error("expected cached vulnerability CVE-2020-1234 to appear in graph enrichment")
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
	for _, unwanted := range []string{
		"osv: cache hit",
		"osv: cache miss",
		"osv: vuln detail cache hit",
		"osv: vuln detail cache miss",
		"osv: fetching vuln detail from API",
	} {
		if strings.Contains(logOutput, unwanted) {
			t.Fatalf("expected aggregated logging to omit %q, got:\n%s", unwanted, logOutput)
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

	pkg := &sdk.Package{
		ID:        "npm:lodash:4.17.15",
		Name:      "lodash",
		Version:   "4.17.15",
		PURL:      "pkg:npm/lodash@4.17.15",
		Ecosystem: "npm",
		Licenses:  []sdk.PackageLicense{{Value: "MIT"}},
	}
	g := sdk.New()
	if err := g.AddNode(pkg); err != nil {
		t.Fatalf("AddPackage: %v", err)
	}

	result, err := aud.Match(context.Background(), sdk.MatchRequest{
		Graph: g,
		Mode:  sdk.TargetModeFullGraph,
	})
	if err != nil {
		t.Fatalf("Match returned error on API failure (should be non-fatal): %v", err)
	}
	_ = result // partial results are acceptable
}

// --- KEV enrichment ---

func TestMarkKEVFindings_AppendsReason(t *testing.T) {
	catalog := &KEVCatalog{ids: map[string]struct{}{"CVE-2021-44228": {}}}

	findings := []sdk.Finding{
		{ID: "CVE-2021-44228", Severity: "critical", Reasons: []string{"existing reason"}},
		{ID: "CVE-2099-9999", Severity: "medium", Reasons: nil},
	}
	marked := markKEVFindings(findings, catalog)

	type result struct {
		id     string
		hasKEV bool
	}
	want := []result{
		{"CVE-2021-44228", true},
		{"CVE-2099-9999", false},
	}

	for i, w := range want {
		f := marked[i]
		kevFound := false
		for _, r := range f.Reasons {
			if strings.HasPrefix(r, "CISA KEV:") {
				kevFound = true
				break
			}
		}
		if kevFound != w.hasKEV {
			t.Errorf("finding %q: KEV reason present = %v, want %v (reasons: %v)", w.id, kevFound, w.hasKEV, f.Reasons)
		}
	}
}

// --- severity extraction ---

func TestCvssScoreToBand(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{9.0, "critical"},
		{9.5, "critical"},
		{10.0, "critical"},
		{7.0, "high"},
		{8.9, "high"},
		{4.0, "medium"},
		{6.9, "medium"},
		{0.1, "low"},
		{3.9, "low"},
		{0.0, "low"},
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
		{
			name: "numeric score",
			kind: "CVSS_V3",
			raw:  "7.5",
			want: 7.5,
		},
		{
			name: "vector with explicit prefix",
			kind: "CVSS_V3",
			raw:  "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L",
			want: 2.5,
		},
		{
			name: "vector inferred from severity type",
			kind: "CVSS_V31",
			raw:  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			want: 9.8,
		},
		{
			name: "v2 vector",
			kind: "CVSS_V2",
			raw:  "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			want: 7.5,
		},
		{
			name: "v4 vector inferred from severity type",
			kind: "CVSS_V4",
			raw:  "AV:L/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
			want: 2.0,
		},
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
	got := extractSeverity([]OsvSeverity{{
		Type:  "CVSS_V3",
		Score: "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L",
	}})

	if got != "low" {
		t.Fatalf("extractSeverity() = %q, want %q", got, "low")
	}
}

func TestExtractSeverity_PrefersHigherVersion(t *testing.T) {
	got := extractSeverity([]OsvSeverity{
		{
			Type:  "CVSS_V2",
			Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
		},
		{
			Type:  "CVSS_V4",
			Score: "AV:L/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
		},
	})

	if got != "low" {
		t.Fatalf("extractSeverity() = %q, want %q", got, "low")
	}
}
