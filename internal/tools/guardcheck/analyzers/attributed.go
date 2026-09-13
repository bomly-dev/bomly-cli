package analyzers

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/typeutil"
)

// Attributed reports a detection result that carries graphs and is returned
// without going through detectors.Attributed or detectors.Unattributed.
//
// A result that carries graphs but skips Attributed ships locations with
// nothing to join reachability evidence to: the module root is the join key
// ADR-0037 defines, and a detector that forgets it leaves every site
// unattributed for the whole pipeline. Wrapping the returned literal is one
// line, which is exactly the kind of rule that gets forgotten.
//
// The exemption is typed, not listed: a detector with no module root to name
// returns through Unattributed with its reason as an argument, and this
// analyzer checks that the reason is present and that the wrapped literal
// actually names Graphs, so an exemption cannot be empty or stale (ADR-0044
// rule 5).
//
// The rule matches a literal in a return statement, as the regex it replaced
// did; a literal built into a variable and returned later is not seen.
var Attributed = &analysis.Analyzer{
	Name: "attributed",
	Doc:  "reports a detection result returned with graphs but without detectors.Attributed or a reasoned detectors.Unattributed",
	Run:  runAttributed,
}

func runAttributed(pass *analysis.Pass) (any, error) {
	for _, file := range shippedFiles(pass) {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.ReturnStmt:
				for _, result := range n.Results {
					if lit := detectionResultWithGraphs(pass, result); lit != nil {
						pass.Reportf(lit.Pos(),
							"returns graphs without recording which module root produced each site; wrap the result in detectors.Attributed, or in detectors.Unattributed with the reason there is no root to name")
					}
				}
			case *ast.CallExpr:
				fn, _ := typeutil.Callee(pass.TypesInfo, n).(*types.Func)
				if funcIn(fn, detectorsPath, "Unattributed") {
					checkUnattributed(pass, n)
				}
			}
			return true
		})
	}
	return nil, nil
}

// detectionResultWithGraphs returns expr when it is an sdk.DetectionResult
// literal that names Graphs, and nil otherwise.
func detectionResultWithGraphs(pass *analysis.Pass, expr ast.Expr) *ast.CompositeLit {
	lit, ok := expr.(*ast.CompositeLit)
	if !ok || !isNamed(pass.TypesInfo.TypeOf(lit), sdkPath, "DetectionResult") {
		return nil
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Graphs" {
			return lit
		}
	}
	return nil
}

func checkUnattributed(pass *analysis.Pass, call *ast.CallExpr) {
	if len(call.Args) != 2 {
		return
	}
	if detectionResultWithGraphs(pass, call.Args[0]) == nil {
		pass.Reportf(call.Args[0].Pos(),
			"detectors.Unattributed wraps a result that does not name Graphs; the exemption is stale or covers nothing")
	}
	reason, ok := call.Args[1].(*ast.BasicLit)
	if !ok || reason.Kind != token.STRING {
		pass.Reportf(call.Args[1].Pos(), "detectors.Unattributed needs its reason as a string literal, so a reader finds it at the site")
		return
	}
	if value, err := strconv.Unquote(reason.Value); err != nil || value == "" {
		pass.Reportf(reason.Pos(), "detectors.Unattributed needs a non-empty reason")
	}
}
