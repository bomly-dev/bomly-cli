//go:build ignore

// support_matrix_gen generates docs/SUPPORT_MATRIX.md from the support registry.
//
//go:generate go run support_matrix_gen.go
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bomly/bomly-cli/internal/scan"
)

func main() {
	md := scan.RenderSupportMatrixMarkdown()
	outPath := filepath.Join("..", "..", "docs", "SUPPORT_MATRIX.md")
	if err := os.WriteFile(outPath, []byte(md), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", outPath, err)
		os.Exit(1)
	}
	fmt.Printf("generated %s\n", outPath)
}
