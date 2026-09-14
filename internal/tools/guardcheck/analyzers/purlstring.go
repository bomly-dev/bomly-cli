package analyzers

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/analysis"
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
// named constant, or a constant expression, and a local variable whose
// definition in the same file was such a value is tracked in source order,
// so hoisting the prefix into a const or a variable renames the defect
// rather than removing it. A bare literal is data, and a prefix check
// against one is decomposition, not construction; neither is reported.
var PURLString = &analysis.Analyzer{
	Name: "purlstring",
	Doc:  "reports a package URL built by concatenating or formatting a \"pkg:\" value; build it with the SDK",
	Run:  runPURLString,
}

// purlScheme is what a package URL starts with (package-url spec).
const purlScheme = "pkg:"

var printfLike = regexp.MustCompile(`(?i)printf$`)

func runPURLString(pass *analysis.Pass) (any, error) {
	for _, file := range shippedFiles(pass) {
		// Variables defined from a "pkg:" value, marked as the file is read
		// in source order so a definition precedes the uses it taints.
		tainted := map[*types.Var]bool{}
		prefixed := func(expr ast.Expr) bool {
			if tv, ok := pass.TypesInfo.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
				return strings.HasPrefix(constant.StringVal(tv.Value), purlScheme)
			}
			if v := variableOf(pass, expr); v != nil {
				return tainted[v]
			}
			return false
		}
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
				case token.DEFINE, token.ASSIGN:
					if len(n.Lhs) == len(n.Rhs) {
						for i := range n.Lhs {
							if v := variableOf(pass, n.Lhs[i]); v != nil && prefixed(n.Rhs[i]) {
								tainted[v] = true
							}
						}
					}
				}
			case *ast.ValueSpec:
				if len(n.Names) == len(n.Values) {
					for i := range n.Names {
						if v := variableOf(pass, n.Names[i]); v != nil && prefixed(n.Values[i]) {
							tainted[v] = true
						}
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
