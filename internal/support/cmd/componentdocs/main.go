package main

import (
	"fmt"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/support"
)

func main() {
	outputDir := filepath.Join("docs")
	if err := support.WriteComponentDocs(outputDir); err != nil {
		panic(err)
	}
	fmt.Printf("generated %s component docs\n", outputDir)
}
