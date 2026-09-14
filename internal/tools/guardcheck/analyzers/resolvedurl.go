package analyzers

import (
	"go/ast"
	"go/constant"
	"go/token"
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
// reported as an identifier, inside any constant string (which is how
// reflection would reach the field -- the type checker folds a literal, a
// concatenation of pieces and a named constant alike, so splitting the name
// does not hide it), and in a comment. A forbidigo pattern resolves
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
		// A constant expression is reported once, at its outermost node:
		// the pieces of a split name do not contain it and the folded
		// whole does, so descending past a match only finds nothing.
		ast.Inspect(file, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && ident.Name == exportForbiddenName {
				report(ident.Pos(), "as an identifier")
			}
			expr, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			if tv, ok := pass.TypesInfo.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.String &&
				strings.Contains(constant.StringVal(tv.Value), exportForbiddenName) {
				report(expr.Pos(), "inside a string")
				return false
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
