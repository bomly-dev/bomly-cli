package analyzers

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/typeutil"
)

// Attributed reports a detection result that carries graphs and is built
// anywhere but as the argument of detectors.Attributed or
// detectors.Unattributed.
//
// A result that carries graphs but skips Attributed ships locations with
// nothing to join reachability evidence to: the module root is the join key
// ADR-0037 defines, and a detector that forgets it leaves every site
// unattributed for the whole pipeline. Wrapping the literal is one line,
// which is exactly the kind of rule that gets forgotten.
//
// The rule keys on the literal, not on the return statement (ADR-0044 rule
// 1): a result held in a variable and returned later is reported where it
// is built, and so is one wrapped only later, because the wrap belongs at
// the construction site. There is no data flow to reason about and nothing
// for a variable to hide behind.
//
// The exemption is typed, not listed: a detector with no module root to name
// builds its result inside Unattributed with its reason as an argument, and
// this analyzer checks that the reason is present and that the wrapped
// literal actually names Graphs, so an exemption cannot be empty or stale
// (ADR-0044 rule 5).
var Attributed = &analysis.Analyzer{
	Name: "attributed",
	Doc:  "reports a detection result built with graphs outside detectors.Attributed or a reasoned detectors.Unattributed",
	Run:  runAttributed,
}

func runAttributed(pass *analysis.Pass) (any, error) {
	for _, file := range shippedFiles(pass) {
		// A literal that is the argument of a wrapper is marked when the
		// call is visited, which is before the literal itself.
		wrapped := map[*ast.CompositeLit]bool{}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				fn, _ := typeutil.Callee(pass.TypesInfo, n).(*types.Func)
				isAttributed := funcIn(fn, detectorsPath, "Attributed")
				isUnattributed := funcIn(fn, detectorsPath, "Unattributed")
				if !isAttributed && !isUnattributed {
					return true
				}
				if len(n.Args) > 0 {
					if lit, ok := ast.Unparen(n.Args[0]).(*ast.CompositeLit); ok {
						wrapped[lit] = true
					}
				}
				if isUnattributed {
					checkUnattributed(pass, n)
				}
			case *ast.CompositeLit:
				if detectionResultWithGraphs(pass, n) != nil && !wrapped[n] {
					pass.Reportf(n.Pos(),
						"builds a detection result that carries graphs without recording which module root produced each site; build it inside detectors.Attributed, or inside detectors.Unattributed with the reason there is no root to name")
				}
			case *ast.AssignStmt:
				// Graphs set on a result after it was built is the same
				// decision made a line later: a literal-keyed rule would
				// not see it, so the assignment is reported on its own.
				for _, lhs := range n.Lhs {
					if sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == "Graphs" &&
						isNamed(pass.TypesInfo.TypeOf(sel.X), pluginPath, "DetectionResult") {
						pass.Reportf(sel.Pos(),
							"assigns graphs onto a detection result after it was built, which escapes the attribution wrappers; build the result as a literal inside detectors.Attributed or detectors.Unattributed")
					}
				}
			}
			return true
		})
	}
	return nil, nil
}

// detectionResultWithGraphs returns expr when it is a plugin.DetectionResult
// literal that names Graphs, and nil otherwise.
func detectionResultWithGraphs(pass *analysis.Pass, expr ast.Expr) *ast.CompositeLit {
	lit, ok := ast.Unparen(expr).(*ast.CompositeLit)
	if !ok || !isNamed(pass.TypesInfo.TypeOf(lit), pluginPath, "DetectionResult") {
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
