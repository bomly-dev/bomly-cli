package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/support"
)

func main() {
	outputDir := filepath.Join("docs", "schemas")
	paths, err := support.WriteCommandSchemas(outputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	for _, path := range paths {
		fmt.Printf("generated %s\n", path)
	}
}
