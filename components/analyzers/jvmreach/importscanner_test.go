package jvmreach

import (
	"strings"
	"testing"
)

func TestScanImports(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "java single import",
			src:  "package com.example;\nimport com.fasterxml.jackson.databind.ObjectMapper;\n\nclass X {}\n",
			want: []string{"com.fasterxml.jackson.databind.ObjectMapper"},
		},
		{
			name: "java wildcard",
			src:  "import com.foo.*;\n",
			want: []string{"com.foo"},
		},
		{
			name: "java static import drops member",
			src:  "import static org.junit.jupiter.api.Assertions.assertEquals;\n",
			want: []string{"org.junit.jupiter.api.Assertions"},
		},
		{
			name: "kotlin import with alias",
			src:  "import com.foo.Bar as B\n",
			want: []string{"com.foo.Bar"},
		},
		{
			name: "kotlin import wildcard",
			src:  "import com.foo.*\n",
			want: []string{"com.foo"},
		},
		{
			name: "scala selector list",
			src:  "import com.foo.{A, B, C}\n",
			want: []string{"com.foo.A", "com.foo.B", "com.foo.C"},
		},
		{
			name: "scala selector with rename",
			src:  "import com.foo.{Bar => B, Baz}\n",
			want: []string{"com.foo.Bar", "com.foo.Baz"},
		},
		{
			name: "scala wildcard",
			src:  "import com.foo._\n",
			want: []string{"com.foo"},
		},
		{
			name: "scala selector wildcard inside braces",
			src:  "import com.foo.{Bar, _}\n",
			want: []string{"com.foo.Bar", "com.foo"},
		},
		{
			name: "scanner stops after first non-import line",
			src:  "import com.a.A;\nclass X {}\nimport com.b.B;\n",
			want: []string{"com.a.A"},
		},
		{
			name: "block comment stripped",
			src:  "/* preamble */\nimport com.a.A;\n",
			want: []string{"com.a.A"},
		},
		{
			name: "trailing line comment ignored",
			src:  "import com.a.A; // why\n",
			want: []string{"com.a.A"},
		},
		{
			name: "multi-line block comment",
			src:  "/*\n  banner\n*/\nimport com.a.A;\n",
			want: []string{"com.a.A"},
		},
		{
			name: "empty input",
			src:  "",
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanImports(strings.NewReader(tc.src))
			if err != nil {
				t.Fatalf("scanImports err: %v", err)
			}
			gotSlice := mapKeys(got)
			if !equalAsSets(gotSlice, tc.want) {
				t.Errorf("scanImports = %v, want %v", gotSlice, tc.want)
			}
		})
	}
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func equalAsSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]struct{}, len(b))
	for _, v := range b {
		seen[v] = struct{}{}
	}
	for _, v := range a {
		if _, ok := seen[v]; !ok {
			return false
		}
	}
	return true
}
