package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/support"
)

func main() {
	outputPath := filepath.Join("docs", "CONFIG_REFERENCE.md")
	fieldCount, err := support.WriteConfigReference(filepath.Join("internal", "config", "config.go"), outputPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("generated %s (%d fields)\n", outputPath, fieldCount)
}
