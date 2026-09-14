package analyzers

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

// The fixtures under testdata are the standing proof that each rule can fail
// (ADR-0044 rule 6): every forbidden shape carries a `// want` comment and
// sits beside the shape that passes. The fake bomly-sdk and internal/detectors
// packages there carry the real import paths, so the analyzers key on exactly
// what they key on in the tree.

func TestNodeInsert(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), NodeInsert, "github.com/bomly-dev/bomly-cli/internal/nodeinsert")
}

func TestPURLString(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), PURLString, "github.com/bomly-dev/bomly-cli/internal/purlstring")
}

func TestAttributed(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), Attributed, "github.com/bomly-dev/bomly-cli/internal/attributed")
}

func TestResolvedURL(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), ResolvedURL, "github.com/bomly-dev/bomly-cli/internal/resolvedurl")
}
