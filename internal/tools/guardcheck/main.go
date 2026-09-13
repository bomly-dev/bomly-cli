// Command guardcheck runs Bomly's structural house rules as go/analysis
// analyzers.
//
// It is a vet tool: `make guardcheck` builds it and runs
// `go vet -vettool=bin/guardcheck ./internal/...`, so package scope and build
// tags come from the go command and results ride the build cache. Each rule
// is one analyzer under ./analyzers, selectable by its flag (-nodeinsert,
// -purlstring, -attributed); with no flag, all of them run.
//
// Import and identifier bans are not here. Those are depguard and forbidigo
// rules in .golangci.yml; this command holds only the shapes no linter can
// express (ADR-0044, amended for issue #464).
package main

import (
	"golang.org/x/tools/go/analysis/multichecker"

	"github.com/bomly-dev/bomly-cli/internal/tools/guardcheck/analyzers"
)

func main() {
	multichecker.Main(analyzers.NodeInsert, analyzers.PURLString, analyzers.Attributed)
}
