package output_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// presentationPackages are the surfaces that render a scan: the structured
// documents built here, the terminal renderers, the TUI, and the MCP
// projections. They are the four that had each grown their own copy of the
// registry lookup.
var presentationPackages = []string{
	"../output",
	"../cli/render",
	"../tui",
	"../mcp",
}

// registryGet spots a direct PackageRegistry.Get on any receiver spelling --
// `registry.Get(`, `m.registry.Get(`, `in.Registry.Get(` -- because the rule
// is about the call, not about what the variable happens to be named.
var registryGet = regexp.MustCompile(`[Rr]egistry\.Get\(`)

// The lookup this guard protects is four lines long, which is exactly why it
// was written six times and why the copies drifted: half of them trimmed the
// package reference before looking it up and half did not, so whether a stray
// space hid a package depended on which surface the reader was looking at.
// Writing it out by hand is the only way to reintroduce that, so this fails
// when anyone does.
//
// output.RegistryPackage and its siblings are the door. The one file allowed
// to open it is the one that defines them.
func TestPresentationLookupsGoThroughTheSharedHelper(t *testing.T) {
	const helperFile = "registry_lookup.go"

	var offenders []string
	forEachPresentationFile(t, func(path, body string) {
		if filepath.Base(path) == helperFile {
			return
		}
		if registryGet.MatchString(body) {
			offenders = append(offenders, path)
		}
	})
	if len(offenders) > 0 {
		t.Fatalf("these presentation files call PackageRegistry.Get directly, which is how the "+
			"trim-before-lookup rule came to differ per surface; call output.RegistryPackage, "+
			"RegistryPackageForNode, FindingAdvisory, ResolvedLicenses, NodeVulnerabilities or "+
			"IdentifyPackageRef instead: %v", offenders)
	}
}

// A package URL is a grammar, and purlkit owns it (ADR-0038). A presentation
// layer that reaches for packageurl-go directly has started keeping a second
// opinion about what a package URL means -- and, historically, a second table
// of what its types map to.
func TestPresentationNeverParsesPackageURLsDirectly(t *testing.T) {
	const packageURLModule = "github.com/package-url/packageurl-go"

	var offenders []string
	forEachPresentationFile(t, func(path, body string) {
		if strings.Contains(body, packageURLModule) {
			offenders = append(offenders, path)
		}
	})
	if len(offenders) > 0 {
		t.Fatalf("these presentation files import packageurl-go directly; go through "+
			"bomly-sdk/purlkit, which owns package URL semantics: %v", offenders)
	}
}

// forEachPresentationFile visits every non-test Go file in the presentation
// packages, recursively, so a new subpackage inherits the guards.
func forEachPresentationFile(t *testing.T, visit func(path, body string)) {
	t.Helper()
	for _, root := range presentationPackages {
		if _, err := os.Stat(root); err != nil {
			t.Fatalf("stat %s: %v", root, err)
		}
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			visit(path, string(body))
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}
