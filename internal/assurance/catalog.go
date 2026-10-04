package assurance

import (
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
)

// Valid reports whether the evidence level is known.
func (e EvidenceLevel) Valid() bool {
	switch e {
	case EvidenceDeterministic, EvidencePinnedInput, EvidenceSnapshot, EvidenceLiveService:
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
	// Measurements are the metrics of this check that the report compares
	// with the previous release. A metric that is not declared here is still
	// recorded with the check's results; it is just not compared.
	Measurements []Measurement `json:"measurements,omitempty"`
}

// Measurement declares one metric as worth comparing between releases, in
// words a reader who has never seen the check can follow.
//
// The comparison is opt-in on purpose. It used to list every metric two
// reports shared, which put seven statistics of one 30 ms scan on the public
// page under names like cold_ci95_upper_ms, and coloured a 70% "slowdown"
// that was the difference between two CI machines: the same two binaries
// measured the same on one machine. A number belongs here only when a change
// in it says something about the release rather than about the runner.
type Measurement struct {
	// Metric is the metric's name in the check result.
	Metric string `json:"metric"`
	// Label is the short public name of the measurement.
	Label string `json:"label"`
	// Description says, in plain language, what is measured and how to read a
	// change in it. The public page shows it beside the label.
	Description string `json:"description"`
	// Better is "lower", "higher", or "neutral".
	Better string `json:"better"`
}

// Input names a pinned repository, fixture, container image, or service an
// evidence claim depends on.
type Input struct {
	Kind     string `json:"kind"`
	Location string `json:"location"`
	Ref      string `json:"ref,omitempty"`
	Revision string `json:"revision,omitempty"`
}

// EvidenceArtifact is a repository file that records an evidence claim's result.
//
// It is named by path and nothing else. A file in this repository is already
// content-addressed by git: a release tag and a path identify exact bytes, and
// the report records the commit. A checksum stored beside the path would be a
// second, hand-kept copy of what git knows, and the only thing it could ever
// do is fall behind the file -- which it did, on every golden update, until
// it was removed. What cannot be addressed by this repository's history is
// still pinned where it is named: a git input by revision, a container by
// digest.
type EvidenceArtifact struct {
	Path string `json:"path"`
}

// Evidence is one public claim about Bomly's behavior, proven by a pinned input
// and a committed result file, and backed by a check whose per-release status
// shows whether the claim still holds. A claim that would only restate what its
// check already reports does not belong here — the check card says it once.
type Evidence struct {
	ID            string             `json:"id"`
	Title         string             `json:"title"`
	Area          string             `json:"area"`
	Description   string             `json:"description"`
	EvidenceLevel EvidenceLevel      `json:"evidence_level"`
	CheckID       string             `json:"check_id"`
	Instance      string             `json:"instance,omitempty"`
	Inputs        []Input            `json:"inputs"`
	RequiredTools []string           `json:"required_tools,omitempty"`
	Reproduce     [][]string         `json:"reproduce"`
	Artifacts     []EvidenceArtifact `json:"artifacts"`
	Proves        []string           `json:"proves"`
	Limitations   []string           `json:"limitations"`
}

// ParseCatalog decodes and structurally validates a catalog document. It does
// not touch the filesystem; use VerifyFiles for the repository-side checks.
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
	if err := validateMeasurements(check.Measurements); err != nil {
		return err
	}
	return validateClaims(check.Proves, check.Limitations)
}

func validateMeasurements(measurements []Measurement) error {
	seen := make(map[string]struct{}, len(measurements))
	for _, measurement := range measurements {
		if strings.TrimSpace(measurement.Metric) == "" {
			return errCatalog("a measurement must name its metric")
		}
		if _, exists := seen[measurement.Metric]; exists {
			return fmt.Errorf("duplicate measurement %q", measurement.Metric)
		}
		seen[measurement.Metric] = struct{}{}
		if strings.TrimSpace(measurement.Label) == "" || strings.TrimSpace(measurement.Description) == "" {
			return fmt.Errorf("measurement %q needs a label and a description", measurement.Metric)
		}
		switch measurement.Better {
		case betterLower, betterHigher, betterNeutral:
		default:
			return fmt.Errorf("measurement %q: better must be lower, higher, or neutral, got %q", measurement.Metric, measurement.Better)
		}
	}
	return nil
}

func validateEvidence(evidence Evidence, areas map[string]struct{}, checks map[string]Check) error {
	// Every claim carries the same fields whichever way it is asserted, so the
	// published report can render one shape for all of them.
	if strings.TrimSpace(evidence.Title) == "" || strings.TrimSpace(evidence.Description) == "" {
		return errCatalog("title and description are required")
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
	if len(evidence.Artifacts) == 0 {
		return errCatalog("evidence requires at least one artifact")
	}
	for _, artifact := range evidence.Artifacts {
		if err := validateRepoPath(artifact.Path); err != nil {
			return err
		}
	}
	return validateClaims(evidence.Proves, evidence.Limitations)
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
		return validateRepoPath(input.Location)
	case "container":
		if input.Ref == "" {
			return errCatalog("container input requires an image reference")
		}
		if level == EvidencePinnedInput && !containerDigestPattern.MatchString(input.Ref) {
			return errCatalog("pinned container input requires an immutable sha256 digest")
		}
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

// VerifyFiles confirms every file the catalog names -- each claim's artifacts
// and fixture inputs -- exists inside root as a regular file, and returns how
// many it checked. A claim that points at a file that was renamed or deleted
// would otherwise keep reading as proven.
//
// The count is returned so a caller can refuse a run that reached nothing
// (ADR-0044): a catalog with no files to check and a catalog whose files are
// all present look the same from a nil error.
func (c Catalog) VerifyFiles(root string) (int, error) {
	checked := 0
	for _, evidence := range c.Evidence {
		for _, artifact := range evidence.Artifacts {
			if err := requireRepositoryFile(root, artifact.Path); err != nil {
				return checked, fmt.Errorf("evidence %q: %w", evidence.ID, err)
			}
			checked++
		}
		for _, input := range evidence.Inputs {
			if input.Kind != "fixture" {
				continue
			}
			if err := requireRepositoryFile(root, input.Location); err != nil {
				return checked, fmt.Errorf("evidence %q: %w", evidence.ID, err)
			}
			checked++
		}
	}
	return checked, nil
}

// requireRepositoryFile confirms path names a regular file that stays inside
// root once symlinks are resolved.
func requireRepositoryFile(root, path string) error {
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
