package jsreach

import "testing"

func TestNormalizeBareSpecifier(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"react", "react"},
		{"react/jsx-runtime", "react"},
		{"@scope/pkg", "@scope/pkg"},
		{"@scope/pkg/util", "@scope/pkg"},
		{"@scope/pkg/sub/path", "@scope/pkg"},
		{"./relative", ""},
		{"../up", ""},
		{"/abs/path", ""},
		{"node:fs", ""},
		{"file://x", ""},
		{"data:text/plain,x", ""},
		{"", ""},
		{" ", ""},
		{"@", ""}, // malformed scoped — no name segment
	}
	for _, tc := range cases {
		if got := normalizeBareSpecifier(tc.in); got != tc.want {
			t.Errorf("normalizeBareSpecifier(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExtractImportedPackagesFromMetafile(t *testing.T) {
	metafile := `{
		"inputs": {
			"src/index.js": {
				"imports": [
					{"path": "react", "kind": "import-statement", "external": true},
					{"path": "./util", "kind": "import-statement"},
					{"path": "react/jsx-runtime", "kind": "import-statement", "external": true},
					{"path": "node:fs", "kind": "import-statement"}
				]
			},
			"src/util.js": {
				"imports": [
					{"path": "@scope/pkg/sub", "kind": "require-call", "external": true},
					{"path": "@scope/pkg", "kind": "import-statement", "external": true}
				]
			},
			"node_modules/react/index.js": {
				"imports": []
			}
		}
	}`
	imports, sources, err := extractImportedPackages(metafile)
	if err != nil {
		t.Fatal(err)
	}
	if sources != 2 {
		t.Errorf("sources = %d, want 2 (node_modules input filtered out)", sources)
	}
	wantSet := map[string]bool{"react": true, "@scope/pkg": true}
	if len(imports) != len(wantSet) {
		t.Errorf("imports = %v, want %v", imports, wantSet)
	}
	for k := range wantSet {
		if _, ok := imports[k]; !ok {
			t.Errorf("missing %q from imports: got %v", k, imports)
		}
	}
}

func TestExtractImportedPackagesRejectsBadJSON(t *testing.T) {
	if _, _, err := extractImportedPackages("not-json"); err == nil {
		t.Error("expected parse error for non-JSON input")
	}
}

func TestIsNodeModulesPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"src/index.js", false},
		{"node_modules/react/index.js", true},
		{"packages/foo/node_modules/lib/x.js", true},
		{"src/node_modules.js", false},
	}
	for _, tc := range cases {
		if got := isNodeModulesPath(tc.path); got != tc.want {
			t.Errorf("isNodeModulesPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
