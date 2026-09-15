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
// type checker's object, so a shadowing name is a different graph; any
// other receiver expression (a field, a call) is compared as source text;
// and an assignment of one graph to another inside the function --
// `alias := g`, `alias := h.graph` -- folds the two identities together. The
// lookup's argument is not inspected at all: the regex this replaced
// matched only an identifier there and walked past `g.Node(pkg.NodeID())`
// for as long as it existed. Both calls must resolve to methods of the SDK's
// Graph; a local type with the same method names is not the hazard, and a
// lookup on one graph followed by an insert into another is not either.
//
// Order is source order, except inside a closure: a closure's body runs when
// it is called, not where it is written, so an insert inside one pairs with
// a lookup on the same graph anywhere in the enclosing function. That errs
// toward reporting a closure that is defined early and never called after
// the lookup, which is the direction that gets looked at (ADR-0044).
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
	graph     string // the identity the receiver resolves to
	text      string // the receiver as written, for the message
	call      *ast.CallExpr
	inClosure bool // inside a func literal nested in the body being scanned
}

func reportLookupThenInsert(pass *analysis.Pass, body *ast.BlockStmt) {
	aliases := graphAliases(pass, body)
	var lookups, inserts []graphCall
	var collect func(root ast.Node, inClosure bool)
	collect = func(root ast.Node, inClosure bool) {
		ast.Inspect(root, func(n ast.Node) bool {
			if lit, ok := n.(*ast.FuncLit); ok {
				collect(lit.Body, true)
				return false
			}
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
				lookups = append(lookups, graphCall{aliases.identity(pass, sel.X), types.ExprString(sel.X), call, inClosure})
			case methodOn(fn, sdkPath, "Graph", "AddNode"):
				inserts = append(inserts, graphCall{aliases.identity(pass, sel.X), types.ExprString(sel.X), call, inClosure})
			}
			return true
		})
	}
	collect(body, false)
	for _, lookup := range lookups {
		for _, insert := range inserts {
			// An insert inside a closure runs when the closure is called,
			// which can be after a lookup written below it.
			if insert.graph == lookup.graph && (insert.inClosure || insert.call.Pos() > lookup.call.Pos()) {
				pass.Reportf(lookup.call.Pos(),
					"lookup-then-insert on %s decides by hand what happens to a duplicate node; call detectorkit.EnsureNode",
					lookup.text)
				break
			}
		}
	}
}

// aliasSet folds graph expressions that one function assigns to each other:
// after `alias := g` or `alias := h.graph`, both names are one graph.
// Union-find over receiver identities -- the type checker's variable object
// for a plain name, which is what makes a shadowing `g` in an inner scope a
// different graph rather than the same name, and the source text for a
// field or a call.
//
// The union is function-wide and not order-sensitive: a variable reassigned
// to another graph keeps both identities folded for the whole body. That
// errs toward reporting -- a lookup on one graph followed by an insert on
// the other through the same name is reported, not missed -- and a red that
// names both call sites is the direction that gets looked at (ADR-0044).
// Order-sensitive value tracking would need SSA, and what it would buy is
// silence on a function that swaps graphs under one name, which is a shape
// to restructure rather than to bless.
type aliasSet struct {
	parent map[string]string
}

func graphAliases(pass *analysis.Pass, body *ast.BlockStmt) *aliasSet {
	set := &aliasSet{parent: map[string]string{}}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if (n.Tok == token.DEFINE || n.Tok == token.ASSIGN) && len(n.Lhs) == len(n.Rhs) {
				for i := range n.Lhs {
					set.unite(pass, n.Lhs[i], n.Rhs[i])
				}
			}
		case *ast.ValueSpec:
			if len(n.Names) == len(n.Values) {
				for i := range n.Names {
					set.unite(pass, n.Names[i], n.Values[i])
				}
			}
		}
		return true
	})
	return set
}

func (s *aliasSet) find(key string) string {
	for {
		p, ok := s.parent[key]
		if !ok || p == key {
			return key
		}
		key = p
	}
}

// unite joins two graph expressions; anything that is not an SDK graph is
// ignored, so an assignment of a node or an ID never folds two graphs.
func (s *aliasSet) unite(pass *analysis.Pass, a, b ast.Expr) {
	if !isNamed(pass.TypesInfo.TypeOf(a), sdkPath, "Graph") || !isNamed(pass.TypesInfo.TypeOf(b), sdkPath, "Graph") {
		return
	}
	ra, rb := s.find(receiverIdentity(pass, a)), s.find(receiverIdentity(pass, b))
	if ra != rb {
		s.parent[ra] = rb
	}
}

// identity returns a key that is equal for two receiver expressions exactly
// when they name the same graph as far as this function can tell.
func (s *aliasSet) identity(pass *analysis.Pass, receiver ast.Expr) string {
	return s.find(receiverIdentity(pass, receiver))
}

// receiverIdentity is the key before aliases are folded: the variable object
// for a plain name, the source text for anything else.
func receiverIdentity(pass *analysis.Pass, receiver ast.Expr) string {
	if v := variableOf(pass, receiver); v != nil {
		return "var " + v.Name() + " " + pass.Fset.Position(v.Pos()).String()
	}
	return "expr " + types.ExprString(ast.Unparen(receiver))
}
