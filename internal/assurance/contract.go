// Package assurance implements Bomly's release assurance framework: the shared
// check-result contract every quality check emits, the declarative catalog that
// declares which checks must exist, and the report the public assurance page
// renders for each release.
package assurance

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// CheckSchema is the schema identifier every check result carries.
const CheckSchema = "bomly.assurance-check/v1"

// MaxResultBytes bounds a single check-result document.
const MaxResultBytes = 8 << 20

// Stage names the release phase a check belongs to.
type Stage string

// The three release assurance stages.
const (
	// StagePrerequisites runs on the source tree before a release tag exists.
	StagePrerequisites Stage = "prerequisites"
	// StagePreRelease runs inside the release pipeline against the draft release.
	StagePreRelease Stage = "pre-release"
	// StagePostRelease runs after publication against the shipped artifacts.
	StagePostRelease Stage = "post-release"
)

// Stages lists every release assurance stage in execution order.
func Stages() []Stage {
	return []Stage{StagePrerequisites, StagePreRelease, StagePostRelease}
}

// Valid reports whether the stage is one of the three known stages.
func (s Stage) Valid() bool {
	switch s {
	case StagePrerequisites, StagePreRelease, StagePostRelease:
		return true
	default:
		return false
	}
}

// Title returns the human-readable stage name used in reports.
func (s Stage) Title() string {
	switch s {
	case StagePrerequisites:
		return "Release prerequisites"
	case StagePreRelease:
		return "Final pre-release checks"
	case StagePostRelease:
		return "Post-release assessment"
	default:
		return string(s)
	}
}

// Level distinguishes checks that block a release from advisory observations.
type Level string

// Check enforcement levels.
const (
	// LevelGate blocks the stage when it does not pass.
	LevelGate Level = "gate"
	// LevelAdvisory is reported but never blocks a release.
	LevelAdvisory Level = "advisory"
)

// Valid reports whether the level is known.
func (l Level) Valid() bool { return l == LevelGate || l == LevelAdvisory }

// Status is the outcome of a check or check instance.
type Status string

// Check outcomes, ordered from best to worst by Severity.
const (
	// StatusPass means the check completed and every expectation held.
	StatusPass Status = "pass"
	// StatusSkip means the check did not run for a declared reason.
	StatusSkip Status = "skip"
	// StatusMissing means no result was reported for a declared check.
	StatusMissing Status = "missing"
	// StatusDegraded means the check completed with reduced confidence.
	StatusDegraded Status = "degraded"
	// StatusFail means the check did not hold.
	StatusFail Status = "fail"
)

// Valid reports whether the status is one a check result may carry.
func (s Status) Valid() bool {
	switch s {
	case StatusPass, StatusSkip, StatusMissing, StatusDegraded, StatusFail:
		return true
	default:
		return false
	}
}

// Severity ranks statuses so the worst instance decides a merged check.
func (s Status) Severity() int {
	switch s {
	case StatusPass:
		return 0
	case StatusSkip:
		return 1
	case StatusMissing:
		return 2
	case StatusDegraded:
		return 3
	case StatusFail:
		return 4
	default:
		return 5
	}
}

// Worse returns whichever status is more severe.
func Worse(a, b Status) Status {
	if b.Severity() > a.Severity() {
		return b
	}
	return a
}

// Runner records the machine a check instance executed on.
type Runner struct {
	OS        string `json:"os,omitempty"`
	Arch      string `json:"arch,omitempty"`
	GoVersion string `json:"go_version,omitempty"`
}

// Detail is one named sub-result inside a check instance, such as a single
// smoke test, fuzz target, or cross-build target.
type Detail struct {
	Name       string  `json:"name"`
	Status     Status  `json:"status"`
	Note       string  `json:"note,omitempty"`
	DurationMS float64 `json:"duration_ms,omitempty"`
}

// Artifact records a file a check produced or verified.
type Artifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256,omitempty"`
	Bytes  int64  `json:"bytes,omitempty"`
}

// Link is a labelled URL shown alongside a check.
type Link struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// CheckResult is what a single check instance writes when it finishes. One
// file per instance; instances sharing an ID merge into one reported check.
type CheckResult struct {
	SchemaVersion string             `json:"schema_version"`
	ID            string             `json:"id"`
	Instance      string             `json:"instance,omitempty"`
	Stage         Stage              `json:"stage"`
	Level         Level              `json:"level,omitempty"`
	Status        Status             `json:"status"`
	StartedAt     string             `json:"started_at,omitempty"`
	FinishedAt    string             `json:"finished_at,omitempty"`
	DurationMS    float64            `json:"duration_ms,omitempty"`
	Ref           string             `json:"ref,omitempty"`
	Tag           string             `json:"tag,omitempty"`
	Commit        string             `json:"commit,omitempty"`
	Version       string             `json:"version,omitempty"`
	RunURL        string             `json:"run_url,omitempty"`
	Job           string             `json:"job,omitempty"`
	Runner        Runner             `json:"runner,omitempty"`
	Summary       string             `json:"summary"`
	Metrics       map[string]float64 `json:"metrics,omitempty"`
	Details       []Detail           `json:"details,omitempty"`
	Artifacts     []Artifact         `json:"artifacts,omitempty"`
	Links         []Link             `json:"links,omitempty"`
}

var idPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// instancePattern allows the platform and slice names checks report, which
// include dots (ubuntu-24.04) and underscores (linux_amd64).
var instancePattern = regexp.MustCompile(`^[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*$`)

// ParseCheckResult decodes and validates one check-result document.
func ParseCheckResult(data []byte) (CheckResult, error) {
	if len(data) > MaxResultBytes {
		return CheckResult{}, fmt.Errorf("check result is %d bytes, limit is %d", len(data), MaxResultBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var result CheckResult
	if err := decoder.Decode(&result); err != nil {
		return CheckResult{}, fmt.Errorf("decode check result: %w", err)
	}
	if err := ensureEOF(decoder, "check result"); err != nil {
		return CheckResult{}, err
	}
	if err := result.Validate(); err != nil {
		return CheckResult{}, err
	}
	return result, nil
}

// Validate reports whether the check result satisfies the contract.
func (r CheckResult) Validate() error {
	if r.SchemaVersion != CheckSchema {
		return fmt.Errorf("unsupported check-result schema %q", r.SchemaVersion)
	}
	if !idPattern.MatchString(r.ID) {
		return fmt.Errorf("invalid check id %q", r.ID)
	}
	if r.Instance != "" && !instancePattern.MatchString(r.Instance) {
		return fmt.Errorf("check %q has invalid instance %q", r.ID, r.Instance)
	}
	if !r.Stage.Valid() {
		return fmt.Errorf("check %q has unsupported stage %q", r.ID, r.Stage)
	}
	if r.Level != "" && !r.Level.Valid() {
		return fmt.Errorf("check %q has unsupported level %q", r.ID, r.Level)
	}
	if !r.Status.Valid() || r.Status == StatusMissing {
		return fmt.Errorf("check %q has unsupported status %q", r.ID, r.Status)
	}
	if strings.TrimSpace(r.Summary) == "" {
		return fmt.Errorf("check %q requires a summary", r.ID)
	}
	for index, detail := range r.Details {
		if strings.TrimSpace(detail.Name) == "" {
			return fmt.Errorf("check %q detail %d requires a name", r.ID, index+1)
		}
		if !detail.Status.Valid() {
			return fmt.Errorf("check %q detail %q has unsupported status %q", r.ID, detail.Name, detail.Status)
		}
	}
	for index, artifact := range r.Artifacts {
		if strings.TrimSpace(artifact.Name) == "" {
			return fmt.Errorf("check %q artifact %d requires a name", r.ID, index+1)
		}
	}
	for index, link := range r.Links {
		if strings.TrimSpace(link.Label) == "" || strings.TrimSpace(link.URL) == "" {
			return fmt.Errorf("check %q link %d requires a label and url", r.ID, index+1)
		}
	}
	return nil
}

// Key identifies a check instance uniquely within one run.
func (r CheckResult) Key() string {
	if r.Instance == "" {
		return r.ID
	}
	return r.ID + "." + r.Instance
}

// FileName is the on-disk name a check result is written under.
func (r CheckResult) FileName() string { return r.Key() + ".json" }

// Encode renders the check result as indented JSON with a trailing newline.
func (r CheckResult) Encode() ([]byte, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode check result: %w", err)
	}
	return append(data, '\n'), nil
}

// LoadResults reads every check-result document under dir, recursively, so a
// directory of merged CI artifacts can be consumed directly. Files that are not
// check results are ignored; malformed check results are an error.
func LoadResults(dir string) ([]CheckResult, error) {
	var results []CheckResult
	walkErr := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		data, readErr := readBounded(path, MaxResultBytes)
		if readErr != nil {
			return readErr
		}
		if !looksLikeCheckResult(data) {
			return nil
		}
		result, parseErr := ParseCheckResult(data)
		if parseErr != nil {
			return fmt.Errorf("%s: %w", path, parseErr)
		}
		results = append(results, result)
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("load check results from %s: %w", dir, walkErr)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Key() < results[j].Key() })
	return results, nil
}

func looksLikeCheckResult(data []byte) bool {
	var probe struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.SchemaVersion == CheckSchema
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("read %s: file exceeds %d bytes", path, limit)
	}
	return data, nil
}

func ensureEOF(decoder *json.Decoder, what string) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("decode %s: multiple JSON values", what)
	}
	return fmt.Errorf("decode %s trailing data: %w", what, err)
}
