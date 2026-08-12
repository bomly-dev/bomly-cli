package assurance

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type listedPackage struct {
	ImportPath string
	Imports    []string
}

func TestRemediationPackageDependencyBoundaries(t *testing.T) {
	root := repositoryRoot(t)
	const module = "github.com/bomly-dev/bomly-cli/"
	// The shared helper packages live in the SDK module now; the capability
	// they grant (bounded filesystem/subprocess ops, cache filesystem access)
	// is unchanged, so the boundary assertions target the SDK paths.
	const sdkSystem = "github.com/bomly-dev/bomly-sdk/system"
	const sdkFilecache = "github.com/bomly-dev/bomly-sdk/filecache"

	t.Run("central derivation", func(t *testing.T) {
		packages := goListDependencies(t, root, "./internal/remediation")
		assertDirectImportsAbsent(t, packages, module+"internal/remediation", map[string]string{
			"net":        "network access",
			"net/http":   "HTTP access",
			"os":         "filesystem or process environment access",
			"os/exec":    "subprocess execution",
			sdkSystem:    "filesystem or subprocess access",
			sdkFilecache: "cache filesystem access",
		})
		assertDependenciesAbsent(t, packages, map[string]string{
			module + "internal/git":    "Git filesystem or subprocess access",
			sdkFilecache:               "cache filesystem access",
			module + "internal/plugin": "native plugin execution",
			sdkSystem:                  "filesystem or subprocess access",
		})
	})

	// These packages also own detector resolution, so their complete dependency
	// graphs legitimately include the SDK system helpers and os/exec. At package
	// granularity, enforce that remediation hints do not acquire network,
	// cache, plugin, Git, or central-policy dependencies. Request immutability
	// and read-only provider behavior are covered by the remediation contract
	// tests named in EXECUTION_BOUNDARIES.md.
	detectorHintPackages := []struct {
		name string
		path string
	}{
		{name: "shared", path: "./internal/detectors"},
		{name: "cargo", path: "./internal/detectors/cargo"},
		{name: "composer", path: "./internal/detectors/composer"},
		{name: "gomod", path: "./internal/detectors/gomod"},
		{name: "gradle", path: "./internal/detectors/gradle"},
		{name: "maven", path: "./internal/detectors/maven"},
		{name: "bun", path: "./internal/detectors/node/bun"},
		{name: "npm", path: "./internal/detectors/node/npm"},
		{name: "pnpm", path: "./internal/detectors/node/pnpm"},
		{name: "yarn", path: "./internal/detectors/node/yarn"},
		{name: "python", path: "./internal/detectors/python"},
		{name: "ruby", path: "./internal/detectors/ruby"},
	}
	t.Run("detector hint packages", func(t *testing.T) {
		for _, target := range detectorHintPackages {
			target := target
			t.Run(target.name, func(t *testing.T) {
				packages := goListDependencies(t, root, target.path)
				importPath := module + strings.TrimPrefix(target.path, "./")
				assertDirectImportsAbsent(t, packages, importPath, map[string]string{
					"net":                           "network access",
					"net/http":                      "HTTP access",
					module + "internal/git":         "Git access",
					sdkFilecache:                    "cache filesystem access",
					module + "internal/plugin":      "native plugin execution",
					module + "internal/remediation": "central remediation policy",
				})
				assertDependenciesAbsent(t, packages, map[string]string{
					module + "internal/git":         "Git access",
					sdkFilecache:                    "cache filesystem access",
					module + "internal/plugin":      "native plugin execution",
					module + "internal/remediation": "central remediation policy",
				})
			})
		}
	})
}

func goListDependencies(t *testing.T, root, packagePath string) map[string]listedPackage {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "-json", packagePath)
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list dependencies for %s: %v", packagePath, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	packages := map[string]listedPackage{}
	for {
		var listed listedPackage
		err := decoder.Decode(&listed)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode go list output for %s: %v", packagePath, err)
		}
		packages[listed.ImportPath] = listed
	}
	return packages
}

func assertDirectImportsAbsent(t *testing.T, packages map[string]listedPackage, importPath string, forbidden map[string]string) {
	t.Helper()
	target, ok := packages[importPath]
	if !ok {
		t.Fatalf("go list omitted target package %q", importPath)
	}
	for _, imported := range target.Imports {
		if reason, found := forbidden[imported]; found {
			t.Errorf("package %q directly imports %q, which permits %s", importPath, imported, reason)
		}
	}
}

func assertDependenciesAbsent(t *testing.T, packages map[string]listedPackage, forbidden map[string]string) {
	t.Helper()
	for importPath, reason := range forbidden {
		if _, found := packages[importPath]; found {
			t.Errorf("transitive package graph includes %q, which permits %s", importPath, reason)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve assurance test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
}
