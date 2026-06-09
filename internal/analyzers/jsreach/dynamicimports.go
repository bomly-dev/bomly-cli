package jsreach

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// jsDynamicImport matches dynamic-import constructs in JavaScript /
// TypeScript that the static scanner cannot follow:
//
//	require(variable)
//	require(`literal ${interp}`)
//	import(variable)
//	await import(name)
//	System.import(name)
//
// The pattern intentionally fires on any non-string argument inside
// require()/import(). A bare string literal like require("react") is
// excluded — those are statically resolved by the esbuild walk.
var jsDynamicImport = regexp.MustCompile(`(?:\brequire\s*\(\s*(?:[^"'\s)]|` + "`" + `)|\bimport\s*\(\s*(?:[^"'\s)]|` + "`" + `)|\bSystem\.import\s*\(\s*(?:[^"'\s)]|` + "`" + `))`)

// detectDynamicImports walks .js/.jsx/.ts/.tsx/.mjs/.cjs files under
// projectDir and returns true on the first match of a dynamic-import
// construct. Returns false if the walk completes without finding one.
// Skips node_modules and common build outputs to avoid false positives
// from third-party bundled code.
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
			if shouldSkipJSDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isJSSource(d.Name()) {
			return nil
		}
		if fileContainsDynamicImport(path) {
			found = true
		}
		return nil
	})
	return found
}

// fileContainsDynamicImport reads path line-by-line and returns true
// on the first match of jsDynamicImport. The line iterator is bounded
// so a pathologically long line cannot stall the scan.
func fileContainsDynamicImport(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		// Cheap pre-filter: skip lines without "require" or "import"
		// (the regex would discard them anyway, but avoiding the
		// regex on hot lines speeds the walk).
		if !strings.Contains(line, "require") && !strings.Contains(line, "import") {
			continue
		}
		if jsDynamicImport.MatchString(line) {
			return true
		}
	}
	return false
}

// shouldSkipJSDir reports whether a directory should be pruned during
// the dynamic-import walk. Includes node_modules and common build
// outputs so third-party code cannot mask a project's true signal.
func shouldSkipJSDir(name string) bool {
	switch name {
	case "node_modules",
		"dist", "build", "out", "coverage", ".next", ".nuxt", ".cache",
		".git", ".hg", ".svn",
		".idea", ".vscode":
		return true
	}
	return false
}

func isJSSource(name string) bool {
	lower := strings.ToLower(name)
	switch filepath.Ext(lower) {
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx":
		return true
	}
	return false
}
