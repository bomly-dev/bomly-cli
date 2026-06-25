package detectors

import (
	"bufio"
	"os"
	"strings"

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
	candidates := make(map[string][]*sdk.SourcePosition, len(positions))
	for key, pos := range positions {
		if pos == nil {
			continue
		}
		candidates[key] = []*sdk.SourcePosition{pos}
	}
	attachPositionCandidates(g, candidates, func(dep *sdk.Dependency) []string {
		if nameKey == nil {
			return nil
		}
		return []string{nameKey(dep)}
	}, false)
}

// AttachPositionCandidates populates PackageLocation.Position on graph nodes
// using one or more lookup keys per dependency. It preserves multiple
// declaration sites and skips exact duplicate file/line/column entries.
func AttachPositionCandidates(g *sdk.Graph, positions map[string][]*sdk.SourcePosition, keys func(*sdk.Dependency) []string) {
	attachPositionCandidates(g, positions, keys, true)
}

// AppendPosition appends pos under key unless the same file/line/column
// position was already recorded.
func AppendPosition(out map[string][]*sdk.SourcePosition, key string, pos *sdk.SourcePosition) {
	key = strings.TrimSpace(key)
	if key == "" || pos == nil {
		return
	}
	for _, existing := range out[key] {
		if existing.File == pos.File && existing.Line == pos.Line && existing.Column == pos.Column {
			return
		}
	}
	out[key] = append(out[key], pos)
}

func attachPositionCandidates(g *sdk.Graph, positions map[string][]*sdk.SourcePosition, keys func(*sdk.Dependency) []string, exactDuplicate bool) {
	if g == nil || len(positions) == 0 || keys == nil {
		return
	}
	for _, pkg := range g.Nodes() {
		if pkg == nil {
			continue
		}
		for _, key := range keys(pkg) {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			matchedKey := false
			for _, pos := range positions[key] {
				if pos == nil {
					continue
				}
				matchedKey = true
				if hasLocation(pkg.Locations, pos, exactDuplicate) {
					continue
				}
				pkg.Locations = append(pkg.Locations, sdk.PackageLocation{
					RealPath:   pos.File,
					AccessPath: pos.File,
					Position:   pos,
				})
			}
			if matchedKey {
				break
			}
		}
	}
}

func hasLocation(locations []sdk.PackageLocation, pos *sdk.SourcePosition, exactDuplicate bool) bool {
	for _, loc := range locations {
		if loc.RealPath != pos.File {
			continue
		}
		if !exactDuplicate {
			return true
		}
		if loc.Position == nil {
			continue
		}
		if loc.Position.Line == pos.Line && loc.Position.Column == pos.Column && loc.Position.EndLine == pos.EndLine {
			return true
		}
	}
	return false
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
	defer func() { _ = f.Close() }()
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
