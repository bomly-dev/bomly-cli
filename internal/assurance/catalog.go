package assurance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CatalogSchema is the schema identifier of the assurance catalog.
const CatalogSchema = "bomly.assurance-catalog/v1"

// MaxCatalogBytes bounds the catalog document.
const MaxCatalogBytes = 4 << 20

// DefaultCatalogPath is the repository-relative catalog location.
const DefaultCatalogPath = "docs/assurance/catalog.json"

var (
	revisionPattern        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hashPattern            = regexp.MustCompile(`^[0-9a-f]{64}$`)
	containerDigestPattern = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
)

// EvidenceLevel describes how strong a public evidence claim is.
type EvidenceLevel string

// Evidence strength levels, from strongest to weakest guarantee.
const (
	// EvidenceDeterministic is reproducible in process with no external input.
	EvidenceDeterministic EvidenceLevel = "deterministic"
	// EvidencePinnedInput depends on a pinned repository revision or fixture.
	EvidencePinnedInput EvidenceLevel = "pinned-input"
	// EvidenceSnapshot depends on an upstream tag that can move.
	EvidenceSnapshot EvidenceLevel = "snapshot"
	// EvidenceLiveService depends on data from a live service.
	EvidenceLiveService EvidenceLevel = "live-service"
	// EvidenceReleaseArtifact is measured against published release artifacts.
	EvidenceReleaseArtifact EvidenceLevel = "release-artifact"
	// EvidencePlatformMatrix comes from repeated runs across platforms.
	EvidencePlatformMatrix EvidenceLevel = "platform-matrix"
)

// Valid reports whether the evidence level is known.
func (e EvidenceLevel) Valid() bool {
	switch e {
	case EvidenceDeterministic, EvidencePinnedInput, EvidenceSnapshot,
		EvidenceLiveService, EvidenceReleaseArtifact, EvidencePlatformMatrix:
		return true
	default:
		return false
	}
}

// Catalog declares every check the framework expects and every public evidence
// claim those checks back. It is the single source the report is built against.
type Catalog struct {
	SchemaVersion string     `json:"schema_version"`
	Areas         []Area     `json:"areas"`
	Checks        []Check    `json:"checks"`
	Evidence      []Evidence `json:"evidence"`
}

// Area groups related checks and evidence for presentation.
type Area struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// Source records which workflow and job produce a check's results.
type Source struct {
	Workflow string `json:"workflow"`
	Job      string `json:"job"`
}

// ExpectedInstance declares one matrix leg a check must report.
type ExpectedInstance struct {
	Name       string   `json:"name"`
	Ecosystems []string `json:"ecosystems,omitempty"`
	Platform   string   `json:"platform,omitempty"`
}

// Check declares one quality check: which stage runs it, whether it gates the
// release, which instances must report, and what it does and does not prove.
type Check struct {
	ID                string             `json:"id"`
	Title             string             `json:"title"`
	Area              string             `json:"area"`
	Stage             Stage              `json:"stage"`
	Level             Level              `json:"level"`
	Description       string             `json:"description"`
	Source            Source             `json:"source"`
	ExpectedInstances []ExpectedInstance `json:"expected_instances,omitempty"`
	Reproduce         [][]string         `json:"reproduce,omitempty"`
	Proves            []string           `json:"proves"`
	Limitations       []string           `json:"limitations"`
}

// Input names a pinned repository, fixture, container image, or service an
// evidence claim depends on.
type Input struct {
	Kind     string `json:"kind"`
	Location string `json:"location"`
	Ref      string `json:"ref,omitempty"`
	Revision string `json:"revision,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

// EvidenceArtifact is a repository file that records an evidence claim's result.
type EvidenceArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Evidence is one public claim about Bomly's behavior, backed by a check whose
// per-release status shows whether the claim still holds.
type Evidence struct {
	ID            string             `json:"id"`
	Title         string             `json:"title"`
	Area          string             `json:"area"`
	EvidenceLevel EvidenceLevel      `json:"evidence_level"`
	CheckID       string             `json:"check_id"`
	Instance      string             `json:"instance,omitempty"`
	Inputs        []Input            `json:"inputs"`
	RequiredTools []string           `json:"required_tools,omitempty"`
	Reproduce     [][]string         `json:"reproduce"`
	Artifacts     []EvidenceArtifact `json:"artifacts,omitempty"`
	Proves        []string           `json:"proves"`
	Limitations   []string           `json:"limitations"`
}

// ParseCatalog decodes and structurally validates a catalog document. It does
// not touch the filesystem; use VerifyArtifacts for the repository-side checks.
func ParseCatalog(data []byte) (Catalog, error) {
	if len(data) > MaxCatalogBytes {
		return Catalog{}, fmt.Errorf("catalog is %d bytes, limit is %d", len(data), MaxCatalogBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var catalog Catalog
	if err := decoder.Decode(&catalog); err != nil {
		return Catalog{}, fmt.Errorf("decode assurance catalog: %w", err)
	}
	if err := ensureEOF(decoder, "assurance catalog"); err != nil {
		return Catalog{}, err
	}
	if err := catalog.Validate(); err != nil {
		return Catalog{}, err
	}
	return catalog, nil
}

// LoadCatalog reads and validates the catalog at path.
func LoadCatalog(path string) (Catalog, error) {
	data, err := readBounded(path, MaxCatalogBytes)
	if err != nil {
		return Catalog{}, err
	}
	return ParseCatalog(data)
}

// Validate reports whether the catalog is internally consistent.
func (c Catalog) Validate() error {
	if c.SchemaVersion != CatalogSchema {
		return fmt.Errorf("unsupported assurance catalog schema %q", c.SchemaVersion)
	}
	if len(c.Areas) == 0 {
		return errCatalog("catalog declares no areas")
	}
	areas := make(map[string]struct{}, len(c.Areas))
	for index, area := range c.Areas {
		if !idPattern.MatchString(area.ID) {
			return fmt.Errorf("area %d has invalid id %q", index+1, area.ID)
		}
		if _, exists := areas[area.ID]; exists {
			return fmt.Errorf("duplicate area %q", area.ID)
		}
		if strings.TrimSpace(area.Title) == "" || strings.TrimSpace(area.Description) == "" {
			return fmt.Errorf("area %q requires a title and description", area.ID)
		}
		areas[area.ID] = struct{}{}
	}
	if len(c.Checks) == 0 {
		return errCatalog("catalog declares no checks")
	}
	checks := make(map[string]Check, len(c.Checks))
	previous := ""
	for index, check := range c.Checks {
		if !idPattern.MatchString(check.ID) {
			return fmt.Errorf("check %d has invalid id %q", index+1, check.ID)
		}
		if _, exists := checks[check.ID]; exists {
			return fmt.Errorf("duplicate check %q", check.ID)
		}
		if previous != "" && check.ID < previous {
			return fmt.Errorf("checks are not sorted by id: %q follows %q", check.ID, previous)
		}
		previous = check.ID
		if err := validateCheck(check, areas); err != nil {
			return fmt.Errorf("check %q: %w", check.ID, err)
		}
		checks[check.ID] = check
	}
	if len(c.Evidence) == 0 {
		return errCatalog("catalog declares no evidence")
	}
	seenEvidence := make(map[string]struct{}, len(c.Evidence))
	previous = ""
	for index, evidence := range c.Evidence {
		if !idPattern.MatchString(evidence.ID) {
			return fmt.Errorf("evidence %d has invalid id %q", index+1, evidence.ID)
		}
		if _, exists := seenEvidence[evidence.ID]; exists {
			return fmt.Errorf("duplicate evidence %q", evidence.ID)
		}
		if previous != "" && evidence.ID < previous {
			return fmt.Errorf("evidence is not sorted by id: %q follows %q", evidence.ID, previous)
		}
		previous = evidence.ID
		seenEvidence[evidence.ID] = struct{}{}
		if err := validateEvidence(evidence, areas, checks); err != nil {
			return fmt.Errorf("evidence %q: %w", evidence.ID, err)
		}
	}
	return nil
}

func validateCheck(check Check, areas map[string]struct{}) error {
	if strings.TrimSpace(check.Title) == "" || strings.TrimSpace(check.Description) == "" {
		return errCatalog("title and description are required")
	}
	if _, exists := areas[check.Area]; !exists {
		return fmt.Errorf("unknown area %q", check.Area)
	}
	if !check.Stage.Valid() {
		return fmt.Errorf("unsupported stage %q", check.Stage)
	}
	if !check.Level.Valid() {
		return fmt.Errorf("unsupported level %q", check.Level)
	}
	if strings.TrimSpace(check.Source.Workflow) == "" || strings.TrimSpace(check.Source.Job) == "" {
		return errCatalog("source workflow and job are required")
	}
	seen := make(map[string]struct{}, len(check.ExpectedInstances))
	for _, instance := range check.ExpectedInstances {
		if !instancePattern.MatchString(instance.Name) {
			return fmt.Errorf("invalid expected instance %q", instance.Name)
		}
		if _, exists := seen[instance.Name]; exists {
			return fmt.Errorf("duplicate expected instance %q", instance.Name)
		}
		seen[instance.Name] = struct{}{}
	}
	if err := validateCommands(check.Reproduce); err != nil {
		return err
	}
	return validateClaims(check.Proves, check.Limitations)
}

func validateEvidence(evidence Evidence, areas map[string]struct{}, checks map[string]Check) error {
	if strings.TrimSpace(evidence.Title) == "" {
		return errCatalog("title is required")
	}
	if _, exists := areas[evidence.Area]; !exists {
		return fmt.Errorf("unknown area %q", evidence.Area)
	}
	if !evidence.EvidenceLevel.Valid() {
		return fmt.Errorf("unsupported evidence level %q", evidence.EvidenceLevel)
	}
	check, exists := checks[evidence.CheckID]
	if !exists {
		return fmt.Errorf("unknown backing check %q", evidence.CheckID)
	}
	if evidence.Instance != "" {
		if !instancePattern.MatchString(evidence.Instance) {
			return fmt.Errorf("invalid instance %q", evidence.Instance)
		}
		if !hasInstance(check, evidence.Instance) {
			return fmt.Errorf("check %q does not declare instance %q", evidence.CheckID, evidence.Instance)
		}
	}
	if len(evidence.Inputs) == 0 {
		return errCatalog("at least one input is required")
	}
	for _, input := range evidence.Inputs {
		if err := validateInput(evidence.EvidenceLevel, input); err != nil {
			return err
		}
	}
	if len(evidence.Reproduce) == 0 {
		return errCatalog("at least one reproduction command is required")
	}
	if err := validateCommands(evidence.Reproduce); err != nil {
		return err
	}
	if len(evidence.Artifacts) == 0 && requiresArtifact(evidence) {
		return errCatalog("repository-backed evidence requires at least one hashed artifact")
	}
	for _, artifact := range evidence.Artifacts {
		if !hashPattern.MatchString(artifact.SHA256) {
			return fmt.Errorf("artifact %q has an invalid SHA-256 hash", artifact.Path)
		}
		if err := validateRepoPath(artifact.Path); err != nil {
			return err
		}
	}
	return validateClaims(evidence.Proves, evidence.Limitations)
}

// requiresArtifact reports whether an evidence claim must point at a hashed
// repository file. Claims proven by committed fixtures and goldens must; claims
// proven by running a workflow against a release are recorded by the per-release
// check result instead.
func requiresArtifact(evidence Evidence) bool {
	switch evidence.EvidenceLevel {
	case EvidenceDeterministic, EvidencePinnedInput, EvidenceSnapshot, EvidenceLiveService:
		return true
	default:
		return false
	}
}

func hasInstance(check Check, name string) bool {
	for _, instance := range check.ExpectedInstances {
		if instance.Name == name {
			return true
		}
	}
	return false
}

func validateInput(level EvidenceLevel, input Input) error {
	if strings.TrimSpace(input.Location) == "" {
		return errCatalog("input location is required")
	}
	switch input.Kind {
	case "git":
		if !revisionPattern.MatchString(input.Revision) {
			return errCatalog("git input requires a full lowercase commit revision")
		}
	case "fixture":
		if !hashPattern.MatchString(input.SHA256) {
			return errCatalog("fixture input requires a SHA-256 hash")
		}
		return validateRepoPath(input.Location)
	case "container":
		if input.Ref == "" {
			return errCatalog("container input requires an image reference")
		}
		if level == EvidencePinnedInput && !containerDigestPattern.MatchString(input.Ref) {
			return errCatalog("pinned container input requires an immutable sha256 digest")
		}
	case "release", "service", "workflow":
		// A published release asset, an external service, or a CI workflow:
		// identified by location. The per-release check result is the record
		// that it ran, so there is no repository hash to pin.
	default:
		return fmt.Errorf("unsupported input kind %q", input.Kind)
	}
	return nil
}

func validateCommands(commands [][]string) error {
	for index, command := range commands {
		if len(command) == 0 {
			return fmt.Errorf("command %d is empty", index+1)
		}
		for _, argument := range command {
			if argument == "" {
				return fmt.Errorf("command %d contains an empty argument", index+1)
			}
		}
	}
	return nil
}

func validateClaims(proves, limitations []string) error {
	if len(proves) == 0 || len(limitations) == 0 {
		return errCatalog("proves and limitations must both be explicit")
	}
	for _, entry := range append(append([]string{}, proves...), limitations...) {
		if strings.TrimSpace(entry) == "" {
			return errCatalog("proves and limitations cannot contain blank entries")
		}
	}
	return nil
}

func validateRepoPath(path string) error {
	clean := filepath.Clean(filepath.FromSlash(path))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q must stay inside the repository", path)
	}
	return nil
}

// VerifyArtifacts confirms every catalog artifact and fixture input still
// matches its recorded hash inside root.
func (c Catalog) VerifyArtifacts(root string) error {
	for _, evidence := range c.Evidence {
		for _, artifact := range evidence.Artifacts {
			if err := verifyHashedFile(root, artifact.Path, artifact.SHA256); err != nil {
				return fmt.Errorf("evidence %q: %w", evidence.ID, err)
			}
		}
		for _, input := range evidence.Inputs {
			if input.Kind != "fixture" {
				continue
			}
			if err := verifyHashedFile(root, input.Location, input.SHA256); err != nil {
				return fmt.Errorf("evidence %q: %w", evidence.ID, err)
			}
		}
	}
	return nil
}

func verifyHashedFile(root, path, want string) error {
	if err := validateRepoPath(path); err != nil {
		return err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return fmt.Errorf("resolve %q: %w", path, err)
	}
	relative, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil {
		return fmt.Errorf("resolve %q relative to repository: %w", path, err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q resolves outside the repository", path)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("inspect %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", path)
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return fmt.Errorf("read %q: %w", path, err)
	}
	sum := sha256.Sum256(data)
	if actual := hex.EncodeToString(sum[:]); actual != want {
		return fmt.Errorf("%q hash is %s, want %s", path, actual, want)
	}
	return nil
}

// ChecksForStage returns the catalog checks that belong to one stage.
func (c Catalog) ChecksForStage(stage Stage) []Check {
	var selected []Check
	for _, check := range c.Checks {
		if check.Stage == stage {
			selected = append(selected, check)
		}
	}
	return selected
}

// Check looks up one catalog check by ID.
func (c Catalog) Check(id string) (Check, bool) {
	for _, check := range c.Checks {
		if check.ID == id {
			return check, true
		}
	}
	return Check{}, false
}

// AreaTitle returns the display title of an area, falling back to its ID.
func (c Catalog) AreaTitle(id string) string {
	for _, area := range c.Areas {
		if area.ID == id {
			return area.Title
		}
	}
	return id
}

type catalogError string

func (e catalogError) Error() string { return string(e) }

func errCatalog(message string) error { return catalogError(message) }
