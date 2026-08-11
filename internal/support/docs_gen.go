package support

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/config"
)

// GenerateDocs runs every documentation generator against outputDir and
// returns one human-readable summary line per artifact, in deterministic
// order. It backs the hidden `bomly internal docs-gen` command so `make
// generate` can regenerate the committed docs/ tree from the built binary
// alone.
//
// Hand-maintained files that live alongside the generated artifacts (for
// example docs/faq.json, docs/manifest.json, and the prose guides) are
// intentionally left untouched.
func GenerateDocs(outputDir string) ([]string, error) {
	if strings.TrimSpace(outputDir) == "" {
		return nil, fmt.Errorf("docs output directory must not be empty")
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", outputDir, err)
	}

	var lines []string

	markdown, fieldCount, err := GenerateConfigReferenceFromSource(config.ResolvedSource())
	if err != nil {
		return nil, fmt.Errorf("generate config reference: %w", err)
	}
	configPath := filepath.Join(outputDir, "CONFIG_REFERENCE.md")
	if err := os.WriteFile(configPath, []byte(markdown), 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", configPath, err)
	}
	lines = append(lines, fmt.Sprintf("generated %s (%d fields)", configPath, fieldCount))

	schemasDir := filepath.Join(outputDir, "schemas")
	schemaPaths, err := WriteCommandSchemas(schemasDir)
	if err != nil {
		return nil, fmt.Errorf("generate command schemas: %w", err)
	}
	docPaths, err := WriteCommandSchemaDocs(schemasDir)
	if err != nil {
		return nil, fmt.Errorf("generate schema docs: %w", err)
	}
	allSchemaPaths := append(append([]string(nil), schemaPaths...), docPaths...)
	sort.Strings(allSchemaPaths)
	for _, path := range allSchemaPaths {
		lines = append(lines, "generated "+path)
	}

	matrixPath := filepath.Join(outputDir, "SUPPORT_MATRIX.md")
	if err := WriteSupportMatrix(matrixPath); err != nil {
		return nil, fmt.Errorf("generate support matrix: %w", err)
	}
	lines = append(lines, "generated "+matrixPath)

	if err := WriteComponentDocs(outputDir); err != nil {
		return nil, fmt.Errorf("generate component docs: %w", err)
	}
	for _, name := range []string{"DETECTORS.md", "MATCHERS.md", "AUDITORS.md"} {
		lines = append(lines, "generated "+filepath.Join(outputDir, name))
	}
	for _, dir := range []string{"detectors", "matchers", "auditors"} {
		pages, err := countMarkdownPages(filepath.Join(outputDir, dir))
		if err != nil {
			return nil, err
		}
		lines = append(lines, fmt.Sprintf("generated %s%c (%d pages)", filepath.Join(outputDir, dir), os.PathSeparator, pages))
	}

	return lines, nil
}

func countMarkdownPages(dir string) (int, error) {
	count := 0
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".md") {
			count++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("count pages in %s: %w", dir, err)
	}
	return count, nil
}
