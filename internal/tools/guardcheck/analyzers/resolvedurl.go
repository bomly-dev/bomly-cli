package analyzers

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// ResolvedURL reports any mention of the name ResolvedURL in a shipped file
// of the package it runs on, which is the export layer.
//
// Raw manifest values -- local paths, credentialed private-registry URLs --
// must be unreachable from export. Export reads Origin.Normalized(), which is
// validated end to end; ResolvedURL is evidence, never output (ADR-0033). The
// structural answer to "could export accidentally leak the raw value" is
// that it cannot name it, and this analyzer keeps that literal: the name is
// reported as an identifier, inside a string (which is how reflection would
// reach the field), and in a comment. A forbidigo pattern resolves
// identifiers and would see none of the last two.
var ResolvedURL = &analysis.Analyzer{
	Name: "resolvedurl",
	Doc:  "reports the name ResolvedURL anywhere in the export layer; export reads Origin.Normalized() only",
	Run:  runResolvedURL,
}

// exportForbiddenName is the raw-evidence field the export layer never names.
const exportForbiddenName = "ResolvedURL"

func runResolvedURL(pass *analysis.Pass) (any, error) {
	for _, file := range shippedFiles(pass) {
		report := func(pos token.Pos, how string) {
			pass.Reportf(pos, "the export layer names %s (%s); it must read Origin.Normalized() only (ADR-0033)", exportForbiddenName, how)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Ident:
				if n.Name == exportForbiddenName {
					report(n.Pos(), "as an identifier")
				}
			case *ast.BasicLit:
				if n.Kind == token.STRING {
					if value, err := strconv.Unquote(n.Value); err == nil && strings.Contains(value, exportForbiddenName) {
						report(n.Pos(), "inside a string")
					}
				}
			}
			return true
		})
		for _, group := range file.Comments {
			for _, comment := range group.List {
				if strings.Contains(comment.Text, exportForbiddenName) {
					report(comment.Pos(), "in a comment")
				}
			}
		}
	}
	return nil, nil
}
