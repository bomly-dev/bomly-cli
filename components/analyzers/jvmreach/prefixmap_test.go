package jvmreach

import (
	"reflect"
	"testing"
)

func TestResolveArtifacts(t *testing.T) {
	cases := []struct {
		fqn  string
		want []string
	}{
		// Longest-prefix matching: databind beats jackson umbrella.
		{"com.fasterxml.jackson.databind.ObjectMapper", []string{"com.fasterxml.jackson.core:jackson-databind"}},
		{"com.fasterxml.jackson.core.JsonParser", []string{"com.fasterxml.jackson.core:jackson-core"}},
		// Log4j publishes two artifacts under the same prefix.
		{"org.apache.logging.log4j.LogManager", []string{"org.apache.logging.log4j:log4j-api", "org.apache.logging.log4j:log4j-core"}},
		// Stdlib: dropped.
		{"java.util.List", nil},
		{"javax.crypto.Cipher", nil},
		{"kotlin.collections.List", nil},
		{"scala.collection.immutable.List", nil},
		// Unknown prefix: dropped (no identity fallback).
		{"com.example.app.Main", nil},
		// Empty / whitespace.
		{"", nil},
		{"   ", nil},
		// Junit5.
		{"org.junit.jupiter.api.Test", []string{"org.junit.jupiter:junit-jupiter-api", "org.junit.jupiter:junit-jupiter-engine"}},
		// Spring sub-package.
		{"org.springframework.web.servlet.DispatcherServlet", []string{"org.springframework:spring-webmvc"}},
		// Apache commons.
		{"org.apache.commons.lang3.StringUtils", []string{"org.apache.commons:commons-lang3"}},
		// Guava.
		{"com.google.common.collect.ImmutableMap", []string{"com.google.guava:guava"}},
	}
	for _, tc := range cases {
		t.Run(tc.fqn, func(t *testing.T) {
			got := resolveArtifacts(tc.fqn)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("resolveArtifacts(%q) = %v, want %v", tc.fqn, got, tc.want)
			}
		})
	}
}

func TestCanonicalCoord(t *testing.T) {
	cases := []struct {
		group, artifact, want string
	}{
		{"com.fasterxml.jackson.core", "jackson-databind", "com.fasterxml.jackson.core:jackson-databind"},
		{"Org.Mockito", "Mockito-Core", "org.mockito:mockito-core"},
		{"", "jackson", ""},
		{"org.example", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.group+":"+tc.artifact, func(t *testing.T) {
			if got := canonicalCoord(tc.group, tc.artifact); got != tc.want {
				t.Errorf("canonicalCoord(%q,%q) = %q, want %q", tc.group, tc.artifact, got, tc.want)
			}
		})
	}
}
