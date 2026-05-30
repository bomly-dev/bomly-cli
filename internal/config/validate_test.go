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

func TestValidateRejectsReachabilityWithoutEnrich(t *testing.T) {
	err := Validate(Resolved{Reachability: true})
	if err == nil {
		t.Fatal("Validate returned nil for --reachability without --enrich; want error")
	}
	if !strings.Contains(err.Error(), "--reachability requires --enrich") {
		t.Errorf("error message = %q, want it to mention '--reachability requires --enrich'", err.Error())
	}
}

func TestValidateAcceptsAuditAndReachabilityWithEnrich(t *testing.T) {
	cases := []struct {
		name string
		cfg  Resolved
	}{
		{"audit + enrich", Resolved{Enrich: true, Audit: true}},
		{"reachability + enrich", Resolved{Enrich: true, Reachability: true}},
		{"all three", Resolved{Enrich: true, Audit: true, Reachability: true}},
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
