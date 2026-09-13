package analyzers

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/typeutil"
)

// NodeInsert reports a lookup on a graph followed, in the same function, by
// an insert on the same graph.
//
// A hand-written "is it already there?" check before an insert is how a dozen
// detectors independently decided what happens to a duplicate record, and the
// answer was usually to drop it, origin and all. Node insertion goes through
// detectorkit.EnsureNode so the behavior is decided once and a detector
// written later inherits it (ADR-0033).
//
// The receiver is compared as source text, so `g.Node(id)` pairs with
// `g.AddNode(n)` and not with an insert on some other graph, and the lookup's
// argument is not inspected at all: the regex this replaced matched only an
// identifier there and walked past `g.Node(pkg.NodeID())` for as long as it
// existed. Both calls must resolve to methods of the SDK's Graph; a local type
// with the same method names is not the hazard.
var NodeInsert = &analysis.Analyzer{
	Name: "nodeinsert",
	Doc:  "reports a graph lookup followed by a hand-written insert; call detectorkit.EnsureNode instead",
	Run:  runNodeInsert,
}

func runNodeInsert(pass *analysis.Pass) (any, error) {
	for _, file := range shippedFiles(pass) {
		ast.Inspect(file, func(n ast.Node) bool {
			switch fn := n.(type) {
			case *ast.FuncDecl:
				if fn.Body != nil {
					reportLookupThenInsert(pass, fn.Body)
				}
				// Closures inside a declaration are scanned with it: a
				// lookup in the function and an insert in a closure it
				// runs is the same linear flow.
				return false
			case *ast.FuncLit:
				// A package-level literal has no enclosing declaration.
				reportLookupThenInsert(pass, fn.Body)
				return false
			}
			return true
		})
	}
	return nil, nil
}

// graphCall is one Node or AddNode call on an SDK graph.
type graphCall struct {
	receiver string
	call     *ast.CallExpr
}

func reportLookupThenInsert(pass *analysis.Pass, body *ast.BlockStmt) {
	var lookups, inserts []graphCall
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		fn, _ := typeutil.Callee(pass.TypesInfo, call).(*types.Func)
		switch {
		case methodOn(fn, sdkPath, "Graph", "Node"):
			lookups = append(lookups, graphCall{types.ExprString(sel.X), call})
		case methodOn(fn, sdkPath, "Graph", "AddNode"):
			inserts = append(inserts, graphCall{types.ExprString(sel.X), call})
		}
		return true
	})
	for _, lookup := range lookups {
		for _, insert := range inserts {
			if insert.receiver == lookup.receiver && insert.call.Pos() > lookup.call.Pos() {
				pass.Reportf(lookup.call.Pos(),
					"lookup-then-insert on %s decides by hand what happens to a duplicate node; call detectorkit.EnsureNode",
					lookup.receiver)
				break
			}
		}
	}
}
