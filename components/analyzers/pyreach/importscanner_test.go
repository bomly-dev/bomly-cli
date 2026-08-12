package pyreach

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
			name: "single import",
			src:  "import requests\n",
			want: []string{"requests"},
		},
		{
			name: "dotted import keeps top-level only",
			src:  "import os.path\n",
			want: []string{"os"},
		},
		{
			name: "comma-separated imports",
			src:  "import os, sys, requests\n",
			want: []string{"os", "sys", "requests"},
		},
		{
			name: "import as alias",
			src:  "import numpy as np\nimport pandas as pd\n",
			want: []string{"numpy", "pandas"},
		},
		{
			name: "from import",
			src:  "from flask import Flask\n",
			want: []string{"flask"},
		},
		{
			name: "from dotted import",
			src:  "from urllib3.util import retry\n",
			want: []string{"urllib3"},
		},
		{
			name: "relative imports skipped",
			src:  "from . import utils\nfrom .foo import bar\nfrom ..pkg import baz\n",
			want: nil,
		},
		{
			name: "trailing comment ignored",
			src:  "import requests  # noqa: F401\n",
			want: []string{"requests"},
		},
		{
			name: "indented import (function-local)",
			src:  "def f():\n    import lazy_dep\n    return lazy_dep.value\n",
			want: []string{"lazy_dep"},
		},
		{
			name: "from-importlib is not a relative import",
			src:  "from importlib import import_module\n",
			want: []string{"importlib"},
		},
		{
			name: "triple-quoted block hides imports",
			src:  "\"\"\"\nimport secret\n\"\"\"\nimport real\n",
			want: []string{"real"},
		},
		{
			name: "single-line docstring does not flip block",
			src:  "\"\"\"oneliner\"\"\"\nimport real\n",
			want: []string{"real"},
		},
		{
			name: "blank lines and comments are ignored",
			src:  "# coding: utf-8\n\nimport os\n\n# trailing comment\n",
			want: []string{"os"},
		},
		{
			name: "ignore non-identifier junk",
			src:  "import 123foo\nimport bar\n",
			want: []string{"bar"},
		},
		{
			name: "from-only list (multi-import on one line)",
			src:  "from typing import List, Dict, Optional\n",
			want: []string{"typing"},
		},
		{
			name: "empty source",
			src:  "",
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanImports(strings.NewReader(tc.src))
			if err != nil {
				t.Fatalf("scanImports returned error: %v", err)
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
