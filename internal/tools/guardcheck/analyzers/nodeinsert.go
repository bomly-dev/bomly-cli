package analyzers

import (
	"go/ast"
	"go/token"
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
// The two calls are paired by which graph they act on, not by how the
// receiver is spelled: a receiver that is a variable is compared as the
// type checker's object, so a shadowing name is a different graph, and
// `alias := g` inside the function folds alias and g together. Any other
// receiver expression (a field, a call) is compared as source text. The
// lookup's argument is not inspected at all: the regex this replaced
// matched only an identifier there and walked past `g.Node(pkg.NodeID())`
// for as long as it existed. Both calls must resolve to methods of the SDK's
// Graph; a local type with the same method names is not the hazard, and a
// lookup on one graph followed by an insert into another is not either.
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
	graph string // the identity the receiver resolves to
	text  string // the receiver as written, for the message
	call  *ast.CallExpr
}

func reportLookupThenInsert(pass *analysis.Pass, body *ast.BlockStmt) {
	aliases := graphAliases(pass, body)
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
			lookups = append(lookups, graphCall{aliases.identity(pass, sel.X), types.ExprString(sel.X), call})
		case methodOn(fn, sdkPath, "Graph", "AddNode"):
			inserts = append(inserts, graphCall{aliases.identity(pass, sel.X), types.ExprString(sel.X), call})
		}
		return true
	})
	for _, lookup := range lookups {
		for _, insert := range inserts {
			if insert.graph == lookup.graph && insert.call.Pos() > lookup.call.Pos() {
				pass.Reportf(lookup.call.Pos(),
					"lookup-then-insert on %s decides by hand what happens to a duplicate node; call detectorkit.EnsureNode",
					lookup.text)
				break
			}
		}
	}
}

// aliasSet folds graph variables that one function assigns to each other:
// after `alias := g`, alias and g are one graph. Union-find over the type
// checker's variable objects, which is what makes a shadowing `g` in an
// inner scope a different graph rather than the same name.
type aliasSet struct {
	parent map[*types.Var]*types.Var
}

func graphAliases(pass *analysis.Pass, body *ast.BlockStmt) *aliasSet {
	set := &aliasSet{parent: map[*types.Var]*types.Var{}}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if (n.Tok == token.DEFINE || n.Tok == token.ASSIGN) && len(n.Lhs) == len(n.Rhs) {
				for i := range n.Lhs {
					set.unite(variableOf(pass, n.Lhs[i]), variableOf(pass, n.Rhs[i]))
				}
			}
		case *ast.ValueSpec:
			if len(n.Names) == len(n.Values) {
				for i := range n.Names {
					set.unite(variableOf(pass, n.Names[i]), variableOf(pass, n.Values[i]))
				}
			}
		}
		return true
	})
	return set
}

func (s *aliasSet) find(v *types.Var) *types.Var {
	for {
		p, ok := s.parent[v]
		if !ok || p == v {
			return v
		}
		v = p
	}
}

// unite joins two graph variables; anything that is not a graph variable is
// ignored, so an assignment of a node or an ID never folds two graphs.
func (s *aliasSet) unite(a, b *types.Var) {
	if a == nil || b == nil || !isNamed(a.Type(), sdkPath, "Graph") || !isNamed(b.Type(), sdkPath, "Graph") {
		return
	}
	ra, rb := s.find(a), s.find(b)
	if ra != rb {
		s.parent[ra] = rb
	}
}

// identity returns a key that is equal for two receiver expressions exactly
// when they name the same graph as far as this function can tell.
func (s *aliasSet) identity(pass *analysis.Pass, receiver ast.Expr) string {
	if v := variableOf(pass, receiver); v != nil {
		root := s.find(v)
		return "var " + root.Name() + " " + pass.Fset.Position(root.Pos()).String()
	}
	return "expr " + types.ExprString(receiver)
}
