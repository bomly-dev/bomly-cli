package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/support"
)

func main() {
	outputPath := filepath.Join("docs", "SUPPORT_MATRIX.md")
	if err := support.WriteSupportMatrix(outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("generated %s\n", outputPath)
}
