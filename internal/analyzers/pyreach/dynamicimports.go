package pyreach

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// pyDynamicImport matches dynamic-import constructs in Python that
// the static scanner cannot follow:
//
//	importlib.import_module(name)         # non-literal arg
//	__import__(name)                       # non-literal arg
//	importlib.util.find_spec(name)         # non-literal arg
//	pkgutil.iter_modules(...)              # any call (signals dynamic discovery)
//	pkg_resources.iter_entry_points(...)   # plugin discovery
//
// The pattern fires when the import-related call is invoked but does
// not statically take a string-literal argument. Bare string-literal
// calls like importlib.import_module("yaml") are excluded because the
// scanner can already see them.
var pyDynamicImport = regexp.MustCompile(
	`(?:\bimportlib\.import_module\s*\(\s*(?:[^"'\s)])|` +
		`\b__import__\s*\(\s*(?:[^"'\s)])|` +
		`\bimportlib\.util\.find_spec\s*\(\s*(?:[^"'\s)])|` +
		`\bpkgutil\.iter_modules\s*\(|` +
		`\bpkg_resources\.iter_entry_points\s*\()`,
)

// detectDynamicImports walks .py files under projectDir and returns
// true on the first match of a dynamic-import construct. Skips venv,
// site-packages, __pycache__, and other directories the regular
// source walker also prunes.
func detectDynamicImports(projectDir string) bool {
	found := false
	_ = filepath.WalkDir(projectDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || found {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path == projectDir {
				return nil
			}
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".py") {
			return nil
		}
		if fileContainsDynamicImport(path) {
			found = true
		}
		return nil
	})
	return found
}

func fileContainsDynamicImport(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		// Pre-filter: skip lines without one of the trigger tokens.
		if !strings.Contains(line, "import_module") &&
			!strings.Contains(line, "__import__") &&
			!strings.Contains(line, "find_spec") &&
			!strings.Contains(line, "iter_modules") &&
			!strings.Contains(line, "iter_entry_points") {
			continue
		}
		if pyDynamicImport.MatchString(line) {
			return true
		}
	}
	return false
}
