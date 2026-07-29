// Command publicevidence validates and displays Bomly's public evidence
// catalog.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	catalogSchema  = "bomly.public-evidence/v1"
	defaultCatalog = "test/evidence/cases.json"
)

var (
	caseIDPattern          = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	revisionPattern        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hashPattern            = regexp.MustCompile(`^[0-9a-f]{64}$`)
	containerDigestPattern = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
)

type catalog struct {
	SchemaVersion string         `json:"schema_version"`
	Cases         []evidenceCase `json:"cases"`
}

type evidenceCase struct {
	ID            string     `json:"id"`
	Title         string     `json:"title"`
	Area          string     `json:"area"`
	EvidenceLevel string     `json:"evidence_level"`
	Inputs        []input    `json:"inputs"`
	RequiredTools []string   `json:"required_tools,omitempty"`
	Reproduce     [][]string `json:"reproduce"`
	Evidence      []artifact `json:"evidence"`
	Proves        []string   `json:"proves"`
	Limitations   []string   `json:"limitations"`
}

type input struct {
	Kind     string `json:"kind"`
	Location string `json:"location"`
	Ref      string `json:"ref,omitempty"`
	Revision string `json:"revision,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

type artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func main() {
	catalogPath := flag.String("catalog", defaultCatalog, "path to the public evidence catalog")
	caseID := flag.String("case", "", "show one evidence case")
	flag.Parse()

	root, err := repositoryRoot()
	if err != nil {
		exitError(err)
	}
	resolvedCatalog := resolveCatalogPath(root, *catalogPath)
	loaded, err := loadCatalog(resolvedCatalog)
	if err != nil {
		exitError(err)
	}
	if err := validateCatalog(root, loaded); err != nil {
		exitError(err)
	}

	selected := loaded.Cases
	if *caseID != "" {
		selected = nil
		for _, current := range loaded.Cases {
			if current.ID == *caseID {
				selected = []evidenceCase{current}
				break
			}
		}
		if len(selected) == 0 {
			exitError(fmt.Errorf("unknown evidence case %q", *caseID))
		}
	}
	printCases(selected)
}

func repositoryRoot() (string, error) {
	current, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve working directory: %w", err)
	}
	for {
		if info, statErr := os.Stat(filepath.Join(current, "go.mod")); statErr == nil && !info.IsDir() {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("find repository root: go.mod not found")
		}
		current = parent
	}
}

func resolveCatalogPath(root, catalogPath string) string {
	resolved := filepath.FromSlash(catalogPath)
	if filepath.IsAbs(resolved) {
		return resolved
	}
	return filepath.Join(root, resolved)
}

func loadCatalog(path string) (catalog, error) {
	file, err := os.Open(path)
	if err != nil {
		return catalog{}, fmt.Errorf("open evidence catalog: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(io.LimitReader(file, 2<<20))
	decoder.DisallowUnknownFields()
	var loaded catalog
	if err := decoder.Decode(&loaded); err != nil {
		return catalog{}, fmt.Errorf("decode evidence catalog: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return catalog{}, err
	}
	return loaded, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("decode evidence catalog: multiple JSON values")
	}
	return fmt.Errorf("decode evidence catalog trailing data: %w", err)
}

func validateCatalog(root string, loaded catalog) error {
	if loaded.SchemaVersion != catalogSchema {
		return fmt.Errorf("unsupported evidence catalog schema %q", loaded.SchemaVersion)
	}
	if len(loaded.Cases) == 0 {
		return errors.New("evidence catalog contains no cases")
	}
	seen := make(map[string]struct{}, len(loaded.Cases))
	previous := ""
	for index, current := range loaded.Cases {
		if !caseIDPattern.MatchString(current.ID) {
			return fmt.Errorf("case %d has invalid id %q", index+1, current.ID)
		}
		if _, exists := seen[current.ID]; exists {
			return fmt.Errorf("duplicate evidence case %q", current.ID)
		}
		seen[current.ID] = struct{}{}
		if previous != "" && current.ID < previous {
			return fmt.Errorf("evidence cases are not sorted: %q follows %q", current.ID, previous)
		}
		previous = current.ID
	}
	for _, current := range loaded.Cases {
		if err := validateCase(root, current); err != nil {
			return fmt.Errorf("case %q: %w", current.ID, err)
		}
	}
	return nil
}

func validateCase(root string, current evidenceCase) error {
	if strings.TrimSpace(current.Title) == "" || strings.TrimSpace(current.Area) == "" {
		return errors.New("title and area are required")
	}
	switch current.EvidenceLevel {
	case "deterministic", "pinned-input", "live-service", "manual-assurance", "snapshot":
	default:
		return fmt.Errorf("unsupported evidence level %q", current.EvidenceLevel)
	}
	if len(current.Inputs) == 0 {
		return errors.New("at least one input is required")
	}
	for _, item := range current.Inputs {
		if err := validateInput(root, current.EvidenceLevel, item); err != nil {
			return err
		}
	}
	if len(current.Reproduce) == 0 {
		return errors.New("at least one reproduction command is required")
	}
	for index, command := range current.Reproduce {
		if len(command) == 0 {
			return fmt.Errorf("reproduction command %d is empty", index+1)
		}
		for _, argument := range command {
			if argument == "" {
				return fmt.Errorf("reproduction command %d contains an empty argument", index+1)
			}
		}
	}
	if len(current.Evidence) == 0 {
		return errors.New("at least one evidence artifact is required")
	}
	for _, item := range current.Evidence {
		if err := validateArtifact(root, item); err != nil {
			return err
		}
	}
	if len(current.Proves) == 0 || len(current.Limitations) == 0 {
		return errors.New("proves and limitations must both be explicit")
	}
	for _, claim := range current.Proves {
		if strings.TrimSpace(claim) == "" {
			return errors.New("proves and limitations cannot contain blank entries")
		}
	}
	for _, limitation := range current.Limitations {
		if strings.TrimSpace(limitation) == "" {
			return errors.New("proves and limitations cannot contain blank entries")
		}
	}
	return nil
}

func validateInput(root, evidenceLevel string, current input) error {
	if strings.TrimSpace(current.Location) == "" {
		return errors.New("input location is required")
	}
	switch current.Kind {
	case "git":
		if !revisionPattern.MatchString(current.Revision) {
			return errors.New("git input requires a full lowercase commit revision")
		}
	case "fixture":
		if !hashPattern.MatchString(current.SHA256) {
			return errors.New("fixture input requires a SHA-256 hash")
		}
		return validateArtifact(root, artifact{Path: current.Location, SHA256: current.SHA256})
	case "container":
		if current.Ref == "" {
			return errors.New("container input requires an image reference")
		}
		if evidenceLevel == "pinned-input" && !containerDigestPattern.MatchString(current.Ref) {
			return errors.New("pinned container input requires an immutable sha256 digest")
		}
	case "workflow":
		if !hashPattern.MatchString(current.SHA256) {
			return errors.New("workflow input requires a SHA-256 hash")
		}
		return validateArtifact(root, artifact{Path: current.Location, SHA256: current.SHA256})
	default:
		return fmt.Errorf("unsupported input kind %q", current.Kind)
	}
	return nil
}

func validateArtifact(root string, item artifact) error {
	if !hashPattern.MatchString(item.SHA256) {
		return fmt.Errorf("artifact %q has an invalid SHA-256 hash", item.Path)
	}
	clean := filepath.Clean(filepath.FromSlash(item.Path))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("artifact path %q must stay inside the repository", item.Path)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	path := filepath.Join(root, clean)
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve artifact %q: %w", item.Path, err)
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedPath)
	if err != nil {
		return fmt.Errorf("resolve artifact %q relative to repository: %w", item.Path, err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("artifact path %q resolves outside the repository", item.Path)
	}
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return fmt.Errorf("inspect artifact %q: %w", item.Path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("artifact %q is not a regular file", item.Path)
	}
	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		return fmt.Errorf("read artifact %q: %w", item.Path, err)
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if actual != item.SHA256 {
		return fmt.Errorf("artifact %q hash is %s, want %s", item.Path, actual, item.SHA256)
	}
	return nil
}

func printCases(cases []evidenceCase) {
	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	fmt.Printf("Verified %d public evidence case(s).\n", len(cases))
	for _, current := range cases {
		fmt.Printf("\n%s — %s\n", current.ID, current.Title)
		fmt.Printf("  Area: %s; evidence: %s\n", current.Area, current.EvidenceLevel)
		for _, command := range current.Reproduce {
			fmt.Printf("  Reproduce: %s\n", shellCommand(command))
		}
		for _, limitation := range current.Limitations {
			fmt.Printf("  Limitation: %s\n", limitation)
		}
	}
}

func shellCommand(command []string) string {
	quoted := make([]string, len(command))
	for index, argument := range command {
		if argument != "" && strings.IndexFunc(argument, func(r rune) bool {
			if (r >= 'a' && r <= 'z') ||
				(r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') {
				return false
			}
			return !strings.ContainsRune("@%_+=:,./-", r)
		}) == -1 {
			quoted[index] = argument
			continue
		}
		quoted[index] = "'" + strings.ReplaceAll(argument, "'", "'\"'\"'") + "'"
	}
	return strings.Join(quoted, " ")
}

func exitError(err error) {
	fmt.Fprintln(os.Stderr, "public evidence:", err)
	os.Exit(1)
}
