package detectors

import (
	"bufio"
	"os"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// AttachPositions populates PackageLocation.Position on graph
// nodes whose normalized key (derived by nameKey) appears in the
// positions map. Nodes already carrying a Location with the same
// RealPath are left untouched.
//
// nameKey returns the lookup key for a graph node. Detectors
// typically derive it from dep.Name, dep.Org+":"+dep.Name, or a
// language-specific normalization. Returning "" skips the node.
func AttachPositions(g *sdk.Graph, positions map[string]*sdk.SourcePosition, nameKey func(*sdk.Dependency) string) {
	if g == nil || len(positions) == 0 || nameKey == nil {
		return
	}
	for _, pkg := range g.Nodes() {
		if pkg == nil {
			continue
		}
		key := nameKey(pkg)
		if key == "" {
			continue
		}
		pos, ok := positions[key]
		if !ok || pos == nil {
			continue
		}
		duplicate := false
		for _, loc := range pkg.Locations {
			if loc.RealPath == pos.File {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		pkg.Locations = append(pkg.Locations, sdk.PackageLocation{
			RealPath:   pos.File,
			AccessPath: pos.File,
			Position:   pos,
		})
	}
}

// ScanLines invokes fn for every line in the file at path. The
// callback receives the 1-based line number and the raw line text
// (without the trailing newline). Returns the underlying scanner
// error if any. Returns nil silently when the file does not exist —
// detector position wiring is best-effort.
func ScanLines(path string, fn func(line int, text string)) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1<<20)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		fn(lineNum, scanner.Text())
	}
	return scanner.Err()
}
