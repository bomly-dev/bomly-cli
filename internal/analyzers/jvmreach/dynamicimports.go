package jvmreach

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// jvmDynamicImport matches JVM reflection-based class-loading
// constructs that the static scanner cannot follow:
//
//	Class.forName(name)            # non-literal arg
//	ClassLoader.loadClass(name)    # non-literal arg
//	cl.loadClass(name)             # any loadClass call on a variable
//	ServiceLoader.load(...)        # plugin discovery
//	ResourceBundle.getBundle(name) # non-literal arg
//
// Matches when the call's first argument is not a string literal.
// Literal-arg calls are not flagged because the import is already
// statically resolvable.
var jvmDynamicImport = regexp.MustCompile(
	`(?:\bClass\.forName\s*\(\s*(?:[^"\s)])|` +
		`\.loadClass\s*\(\s*(?:[^"\s)])|` +
		`\bServiceLoader\.load\s*\(|` +
		`\bResourceBundle\.getBundle\s*\(\s*(?:[^"\s)]))`,
)

// detectDynamicImports walks Java / Kotlin / Scala / Groovy source
// under projectDir and returns true on the first match of a
// reflection-based class load.
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
			if hasProjectMarker(path) {
				return filepath.SkipDir
			}
			if shouldSkipJVMDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isJVMSource(d.Name()) {
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
		if !strings.Contains(line, "forName") &&
			!strings.Contains(line, "loadClass") &&
			!strings.Contains(line, "ServiceLoader") &&
			!strings.Contains(line, "getBundle") {
			continue
		}
		if jvmDynamicImport.MatchString(line) {
			return true
		}
	}
	return false
}

func shouldSkipJVMDir(name string) bool {
	switch name {
	case "target", "build", "out", ".gradle", ".idea", ".vscode",
		".git", ".hg", ".svn",
		"bin", "node_modules":
		return true
	}
	return false
}

func isJVMSource(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".java", ".kt", ".kts", ".scala", ".groovy":
		return true
	}
	return false
}
