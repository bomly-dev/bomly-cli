package config

import (
	"strings"
	"testing"
)

func TestValidateRejectsAuditWithoutEnrich(t *testing.T) {
	err := Validate(Resolved{Audit: true})
	if err == nil {
		t.Fatal("Validate returned nil for --audit without --enrich; want error")
	}
	if !strings.Contains(err.Error(), "--audit requires --enrich") {
		t.Errorf("error message = %q, want it to mention '--audit requires --enrich'", err.Error())
	}
}

func TestValidateRejectsAnalyzeWithoutEnrich(t *testing.T) {
	err := Validate(Resolved{Analyze: true})
	if err == nil {
		t.Fatal("Validate returned nil for --analyze without --enrich; want error")
	}
	if !strings.Contains(err.Error(), "--analyze requires --enrich") {
		t.Errorf("error message = %q, want it to mention '--analyze requires --enrich'", err.Error())
	}
}

func TestValidateAcceptsAuditAndAnalyzeWithEnrich(t *testing.T) {
	cases := []struct {
		name string
		cfg  Resolved
	}{
		{"audit + enrich", Resolved{Enrich: true, Audit: true}},
		{"analyze + enrich", Resolved{Enrich: true, Analyze: true}},
		{"all three", Resolved{Enrich: true, Audit: true, Analyze: true}},
		{"enrich alone", Resolved{Enrich: true}},
		{"none of the three", Resolved{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(tc.cfg); err != nil {
				t.Errorf("Validate(%+v) = %v; want nil", tc.cfg, err)
			}
		})
	}
}

func TestValidateExistingMutualExclusions(t *testing.T) {
	if err := Validate(Resolved{Interactive: true, Format: "json"}); err == nil {
		t.Error("--interactive + --format should still error")
	}
	if err := Validate(Resolved{Quiet: true, Verbosity: 1}); err == nil {
		t.Error("--quiet + --verbose should still error")
	}
}

func TestValidateRejectsInvalidHTTPProxy(t *testing.T) {
	err := Validate(Resolved{HTTPProxy: "proxy.example:8080"})
	if err == nil {
		t.Fatal("Validate returned nil for invalid proxy URL")
	}
	if !strings.Contains(err.Error(), "invalid http_proxy URL") {
		t.Fatalf("error = %q, want invalid http_proxy URL", err.Error())
	}
}

func TestValidateRedactsCredentialsInInvalidHTTPProxy(t *testing.T) {
	err := Validate(Resolved{HTTPProxy: "http://agent:super-secret%zz@proxy.example:8080"})
	if err == nil {
		t.Fatal("Validate returned nil for invalid proxy URL")
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("error leaked proxy password: %q", err.Error())
	}
	if strings.Contains(err.Error(), "agent:") {
		t.Fatalf("error leaked proxy userinfo: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "invalid http_proxy URL") {
		t.Fatalf("error = %q, want invalid http_proxy URL", err.Error())
	}
}

func TestValidateRejectsInvalidHTTPProxyFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  Resolved
		want string
	}{
		{
			name: "unsupported type",
			cfg:  Resolved{HTTPProxyType: "ftp", HTTPProxyHost: "proxy.example", HTTPProxyPort: 8080},
			want: "unsupported http_proxy_type",
		},
		{
			name: "port without host",
			cfg:  Resolved{HTTPProxyPort: 8080},
			want: "http_proxy_port requires http_proxy_host",
		},
		{
			name: "host without port",
			cfg:  Resolved{HTTPProxyHost: "proxy.example"},
			want: "http_proxy_port must be between 1 and 65535",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateRecursiveDiscoveryRules(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Resolved
		wantErr string
	}{
		{"exclude without recursive", Resolved{ExcludePaths: []string{"apps/*"}}, "--exclude requires --recursive"},
		{"negative max depth", Resolved{Recursive: true, MaxDepth: -1}, "--max-depth must be a positive depth or 0 for unlimited"},
		{"recursive with image", Resolved{Recursive: true, Image: "alpine:latest"}, "--recursive cannot be combined with --image"},
		{"recursive with sbom", Resolved{Recursive: true, SBOM: true}, "--recursive cannot be combined with --sbom"},
		{"malformed exclude pattern", Resolved{Recursive: true, ExcludePaths: []string{"[unclosed"}}, "invalid --exclude pattern"},
		{"empty exclude pattern", Resolved{Recursive: true, ExcludePaths: []string{"  "}}, "pattern is empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.cfg)
			if err == nil {
				t.Fatalf("Validate(%+v) = nil; want error containing %q", tc.cfg, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error message = %q, want it to mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateAcceptsRecursiveConfigurations(t *testing.T) {
	cases := []struct {
		name string
		cfg  Resolved
	}{
		{"recursive alone", Resolved{Recursive: true}},
		{"recursive with depth and excludes", Resolved{Recursive: true, MaxDepth: 5, ExcludePaths: []string{"apps/*", "dist"}}},
		{"recursive unlimited depth", Resolved{Recursive: true, MaxDepth: 0}},
		{"non-recursive default depth", Resolved{MaxDepth: 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(tc.cfg); err != nil {
				t.Errorf("Validate(%+v) = %v; want nil", tc.cfg, err)
			}
		})
	}
}

func TestApplyDefaultsSetsMaxDepth(t *testing.T) {
	cfg := Resolved{}
	ApplyDefaults(&cfg)
	if cfg.MaxDepth != 3 {
		t.Fatalf("expected default MaxDepth 3, got %d", cfg.MaxDepth)
	}
	explicit := Resolved{MaxDepth: 7}
	ApplyDefaults(&explicit)
	if explicit.MaxDepth != 7 {
		t.Fatalf("expected explicit MaxDepth 7 to survive defaults, got %d", explicit.MaxDepth)
	}
}
