package analyzers

import (
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// PURLString reports a package URL built from a "pkg:" string literal.
//
// A package URL pasted together from a literal and some escaping is the shape
// that produced a real defect: the SBOM export built its synthesized project
// root with url.PathEscape, which leaves '@' alone, so a project named "app@2"
// exported an identity that read back as "app" at version "2". The separators
// are the specification's to escape, so the parts go into the kit and the
// string comes out (ADR-0038).
//
// Construction is a literal on either side of +, a literal appended with +=,
// or a literal handed to a printf-style call as the format or an argument. A
// bare literal is data, and a prefix check against one is decomposition, not
// construction; neither is reported.
var PURLString = &analysis.Analyzer{
	Name: "purlstring",
	Doc:  "reports a package URL built by concatenating or formatting a \"pkg:\" literal; build it with the SDK",
	Run:  runPURLString,
}

// purlScheme is what a package URL starts with (package-url spec).
const purlScheme = "pkg:"

var printfLike = regexp.MustCompile(`(?i)printf$`)

func runPURLString(pass *analysis.Pass) (any, error) {
	for _, file := range shippedFiles(pass) {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.BinaryExpr:
				if n.Op == token.ADD {
					reportPURLLiteral(pass, n.X)
					reportPURLLiteral(pass, n.Y)
				}
			case *ast.AssignStmt:
				if n.Tok == token.ADD_ASSIGN {
					for _, rhs := range n.Rhs {
						reportPURLLiteral(pass, rhs)
					}
				}
			case *ast.CallExpr:
				if printfLike.MatchString(calleeName(n)) {
					for _, arg := range n.Args {
						reportPURLLiteral(pass, arg)
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

func reportPURLLiteral(pass *analysis.Pass, expr ast.Expr) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil || !strings.HasPrefix(value, purlScheme) {
		return
	}
	pass.Reportf(lit.Pos(),
		"package URL built from a string literal; the specification's escaping applies to the separators too, so build it with sdk.BuildPackageURLFor in a detector or purlkit.Build elsewhere")
}
