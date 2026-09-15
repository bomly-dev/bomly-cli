package analyzers

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/typeutil"
)

// PURLString reports a package URL built from a "pkg:" string.
//
// A package URL pasted together from a literal and some escaping is the shape
// that produced a real defect: the SBOM export built its synthesized project
// root with url.PathEscape, which leaves '@' alone, so a project named "app@2"
// exported an identity that read back as "app" at version "2". The separators
// are the specification's to escape, so the parts go into the kit and the
// string comes out (ADR-0038).
//
// Construction is a "pkg:"-prefixed value on either side of +, appended with
// +=, or handed to a printf-style call. The value need not be a literal at
// the site: the type checker's constant folding answers for a literal, a
// named constant, or a constant expression; and a variable, package-level or
// local, that is ever defined or assigned such a value is found before any
// expression is checked, whatever order the code comes in -- Go lets a
// function name a variable declared below it, and a closure runs after an
// assignment written below it. A call answers too when the function it
// calls can return such a value: a function declared in the package, a
// function literal held in a variable, or -- through an analysis fact -- a
// function in a package this one imports. Hoisting the prefix into a const,
// a variable, or a helper therefore renames the defect rather than removing
// it. A bare
// literal is data, and a prefix check against one is decomposition, not
// construction; neither is reported.
var PURLString = &analysis.Analyzer{
	Name:      "purlstring",
	Doc:       "reports a package URL built by concatenating or formatting a \"pkg:\" value; build it with the SDK",
	Run:       runPURLString,
	FactTypes: []analysis.Fact{new(returnsPURLPrefix)},
}

// returnsPURLPrefix marks a function that can return a "pkg:"-prefixed
// value, so a call to it from another package is a prefix there too.
type returnsPURLPrefix struct{}

// AFact marks returnsPURLPrefix as an analysis fact.
func (*returnsPURLPrefix) AFact() {}

func (*returnsPURLPrefix) String() string { return "returnsPURLPrefix" }

// purlScheme is what a package URL starts with (package-url spec).
const purlScheme = "pkg:"

var printfLike = regexp.MustCompile(`(?i)printf$`)

func runPURLString(pass *analysis.Pass) (any, error) {
	files := shippedFiles(pass)
	// Variables defined or assigned from a "pkg:" value anywhere in the
	// package, found to a fixed point before any expression is checked.
	// Source order says nothing about run order: a package-level variable can
	// be declared below the function that reads it, and a closure can read a
	// local assigned below the closure. A variable ever given a prefix is
	// therefore a prefix everywhere, which errs toward reporting (ADR-0044).
	// Functions that can return such a value are found in the same pass:
	// declared ones by their object, literals by the variable holding them.
	tainted := map[*types.Var]bool{}
	taintedFuncs := map[*types.Func]bool{}
	taintedLits := map[*types.Var]bool{}
	prefixed := func(expr ast.Expr) bool {
		if tv, ok := pass.TypesInfo.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
			return strings.HasPrefix(constant.StringVal(tv.Value), purlScheme)
		}
		if v := variableOf(pass, expr); v != nil {
			return tainted[v]
		}
		call, ok := ast.Unparen(expr).(*ast.CallExpr)
		if !ok {
			return false
		}
		if fn := typeutil.StaticCallee(pass.TypesInfo, call); fn != nil {
			return taintedFuncs[fn] || pass.ImportObjectFact(fn, new(returnsPURLPrefix))
		}
		if v := variableOf(pass, call.Fun); v != nil {
			return taintedLits[v]
		}
		return false
	}
	// returnsPrefix reports whether a function body can return a prefixed
	// value as its single result. A nested literal's returns are its own.
	returnsPrefix := func(ftype *ast.FuncType, body *ast.BlockStmt) bool {
		if body == nil || ftype.Results == nil || ftype.Results.NumFields() != 1 {
			return false
		}
		found := false
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.ReturnStmt:
				switch {
				case len(n.Results) == 1:
					found = found || prefixed(n.Results[0])
				case len(n.Results) == 0 && len(ftype.Results.List[0].Names) == 1:
					found = found || prefixed(ftype.Results.List[0].Names[0])
				}
			}
			return !found
		})
		return found
	}
	for changed := true; changed; {
		changed = false
		taint := func(lhs []ast.Expr, rhs []ast.Expr) {
			if len(lhs) != len(rhs) {
				return
			}
			for i := range lhs {
				v := variableOf(pass, lhs[i])
				if v == nil {
					continue
				}
				if !tainted[v] && prefixed(rhs[i]) {
					tainted[v] = true
					changed = true
				}
				if lit, ok := ast.Unparen(rhs[i]).(*ast.FuncLit); ok && !taintedLits[v] && returnsPrefix(lit.Type, lit.Body) {
					taintedLits[v] = true
					changed = true
				}
			}
		}
		for _, file := range files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncDecl:
					if fn, _ := pass.TypesInfo.Defs[n.Name].(*types.Func); fn != nil && !taintedFuncs[fn] && returnsPrefix(n.Type, n.Body) {
						taintedFuncs[fn] = true
						changed = true
					}
				case *ast.AssignStmt:
					if n.Tok == token.DEFINE || n.Tok == token.ASSIGN {
						taint(n.Lhs, n.Rhs)
					}
				case *ast.ValueSpec:
					names := make([]ast.Expr, len(n.Names))
					for i, name := range n.Names {
						names[i] = name
					}
					taint(names, n.Values)
				}
				return true
			})
		}
	}
	for fn := range taintedFuncs {
		pass.ExportObjectFact(fn, new(returnsPURLPrefix))
	}
	for _, file := range files {
		reported := map[token.Pos]bool{}
		report := func(expr ast.Expr) {
			if prefixed(expr) && !reported[expr.Pos()] {
				reported[expr.Pos()] = true
				pass.Reportf(expr.Pos(),
					"package URL built from a \"pkg:\" string; the specification's escaping applies to the separators too, so build it with sdk.BuildPackageURLFor in a detector or purlkit.Build elsewhere")
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.BinaryExpr:
				if n.Op == token.ADD {
					report(n.X)
					report(n.Y)
				}
			case *ast.AssignStmt:
				switch n.Tok {
				case token.ADD_ASSIGN:
					for _, lhs := range n.Lhs {
						report(lhs)
					}
					for _, rhs := range n.Rhs {
						report(rhs)
					}
				}
			case *ast.CallExpr:
				if printfLike.MatchString(calleeName(n)) {
					for _, arg := range n.Args {
						report(arg)
					}
				}
			}
			return true
		})
	}
	return nil, nil
}

// calleeName is the bare name a call names, qualifier or receiver dropped.
func calleeName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}
