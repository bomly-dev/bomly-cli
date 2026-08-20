package assurance

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ReportSchema is the schema identifier of a per-release assurance report.
const ReportSchema = "bomly.assurance-report/v1"

// IndexSchema is the schema identifier of the release index.
const IndexSchema = "bomly.assurance-index/v1"

// MaxReportBytes bounds a report document.
const MaxReportBytes = 16 << 20

// Release identifies the release a report describes.
type Release struct {
	Tag         string `json:"tag"`
	Version     string `json:"version"`
	Commit      string `json:"commit,omitempty"`
	URL         string `json:"url,omitempty"`
	PublishedAt string `json:"published_at,omitempty"`
}

// Verdict counts outcomes and names the checks that need attention.
type Verdict struct {
	Overall          Status   `json:"overall"`
	Checks           int      `json:"checks"`
	Passed           int      `json:"passed"`
	Failed           int      `json:"failed"`
	Degraded         int      `json:"degraded"`
	Skipped          int      `json:"skipped"`
	Missing          int      `json:"missing"`
	GatesFailed      []string `json:"gates_failed,omitempty"`
	AdvisoriesFailed []string `json:"advisories_failed,omitempty"`
	MissingChecks    []string `json:"missing_checks,omitempty"`
}

// Blocking reports whether the verdict must stop a release.
func (v Verdict) Blocking() bool { return len(v.GatesFailed) > 0 || len(v.MissingChecks) > 0 }

// StageReport is one release stage and the checks it contributed.
type StageReport struct {
	ID       Stage    `json:"id"`
	Title    string   `json:"title"`
	Status   Status   `json:"status"`
	Verdict  Verdict  `json:"verdict"`
	RunURL   string   `json:"run_url,omitempty"`
	CheckIDs []string `json:"check_ids"`
}

// AreaReport summarises one subject area: the checks that cover it and the
// evidence claims made about it. Areas are what the published report is
// organised by, because "what does this tell me about Bomly" is a more useful
// question for a reader than "when in the release did this run".
type AreaReport struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Status      Status   `json:"status"`
	Verdict     Verdict  `json:"verdict"`
	CheckIDs    []string `json:"check_ids,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

// InstanceReport is one reported leg of a check.
type InstanceReport struct {
	Name       string             `json:"name"`
	Status     Status             `json:"status"`
	Summary    string             `json:"summary,omitempty"`
	DurationMS float64            `json:"duration_ms,omitempty"`
	RunURL     string             `json:"run_url,omitempty"`
	Runner     Runner             `json:"runner,omitempty"`
	Metrics    map[string]float64 `json:"metrics,omitempty"`
	Details    []Detail           `json:"details,omitempty"`
	Artifacts  []Artifact         `json:"artifacts,omitempty"`
	Links      []Link             `json:"links,omitempty"`
}

// ReportCheck is one catalog check merged with the results it received.
type ReportCheck struct {
	ID               string             `json:"id"`
	Title            string             `json:"title"`
	Area             string             `json:"area"`
	Stage            Stage              `json:"stage"`
	Level            Level              `json:"level"`
	Description      string             `json:"description"`
	Status           Status             `json:"status"`
	Summary          string             `json:"summary,omitempty"`
	DurationMS       float64            `json:"duration_ms,omitempty"`
	Source           Source             `json:"source"`
	Instances        []InstanceReport   `json:"instances,omitempty"`
	MissingInstances []string           `json:"missing_instances,omitempty"`
	Metrics          map[string]float64 `json:"metrics,omitempty"`
	Reproduce        [][]string         `json:"reproduce,omitempty"`
	Proves           []string           `json:"proves"`
	Limitations      []string           `json:"limitations"`
}

// ReportEvidence is one public claim with the status of the check backing it.
type ReportEvidence struct {
	ID            string             `json:"id"`
	Title         string             `json:"title"`
	Area          string             `json:"area"`
	Description   string             `json:"description"`
	EvidenceLevel EvidenceLevel      `json:"evidence_level"`
	CheckID       string             `json:"check_id"`
	Instance      string             `json:"instance,omitempty"`
	Status        Status             `json:"status"`
	Inputs        []Input            `json:"inputs"`
	RequiredTools []string           `json:"required_tools,omitempty"`
	Reproduce     [][]string         `json:"reproduce"`
	Artifacts     []EvidenceArtifact `json:"artifacts"`
	Proves        []string           `json:"proves"`
	Limitations   []string           `json:"limitations"`
}

// EcosystemCoverage is whether one language or package format was exercised
// for this release. Which check did the exercising is deliberately not part of
// it: the reader's question is "was my ecosystem covered", and answering it
// with a grid of checks invites the false conclusion that a blank cell is a
// gap when the ecosystem was covered by another check.
type EcosystemCoverage struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
}

// Coverage lists every ecosystem any check exercised, worst status first.
type Coverage struct {
	Ecosystems []EcosystemCoverage `json:"ecosystems"`
}

// MetricTrend compares one metric against the previous release's report.
type MetricTrend struct {
	CheckID  string  `json:"check_id"`
	Metric   string  `json:"metric"`
	Previous float64 `json:"previous"`
	Current  float64 `json:"current"`
	Delta    float64 `json:"delta"`
	DeltaPct float64 `json:"delta_pct,omitempty"`
	Better   string  `json:"better"`
}

// StatusChange records a check whose status moved between releases.
type StatusChange struct {
	CheckID  string `json:"check_id"`
	Previous Status `json:"previous"`
	Current  Status `json:"current"`
}

// Trends compares this report against the previous release's report.
type Trends struct {
	PreviousTag string         `json:"previous_tag"`
	Metrics     []MetricTrend  `json:"metrics,omitempty"`
	Changed     []StatusChange `json:"changed,omitempty"`
}

// UnknownResult records a reported check that the catalog does not declare.
type UnknownResult struct {
	ID       string `json:"id"`
	Instance string `json:"instance,omitempty"`
	Stage    Stage  `json:"stage"`
	Status   Status `json:"status"`
}

// Environment records where the checks ran.
type Environment struct {
	Runners     []Runner `json:"runners,omitempty"`
	GeneratedBy string   `json:"generated_by,omitempty"`
}

// Report is the per-release document the public assurance page renders.
type Report struct {
	SchemaVersion string           `json:"schema_version"`
	GeneratedAt   string           `json:"generated_at"`
	Release       Release          `json:"release"`
	Verdict       Verdict          `json:"verdict"`
	Stages        []StageReport    `json:"stages"`
	Areas         []AreaReport     `json:"areas"`
	Checks        []ReportCheck    `json:"checks"`
	Evidence      []ReportEvidence `json:"evidence"`
	Coverage      Coverage         `json:"coverage"`
	Trends        *Trends          `json:"trends,omitempty"`
	Unknown       []UnknownResult  `json:"unknown_results,omitempty"`
	Environment   Environment      `json:"environment"`
}

// Encode renders the report as indented JSON with a trailing newline.
func (r Report) Encode() ([]byte, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode assurance report: %w", err)
	}
	return append(data, '\n'), nil
}

// Check looks up one reported check by ID.
func (r Report) Check(id string) (ReportCheck, bool) {
	for _, check := range r.Checks {
		if check.ID == id {
			return check, true
		}
	}
	return ReportCheck{}, false
}

// ParseReport decodes and structurally validates a report document.
func ParseReport(data []byte) (Report, error) {
	if len(data) > MaxReportBytes {
		return Report{}, fmt.Errorf("assurance report is %d bytes, limit is %d", len(data), MaxReportBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var report Report
	if err := decoder.Decode(&report); err != nil {
		return Report{}, fmt.Errorf("decode assurance report: %w", err)
	}
	if err := ensureEOF(decoder, "assurance report"); err != nil {
		return Report{}, err
	}
	if report.SchemaVersion != ReportSchema {
		return Report{}, fmt.Errorf("unsupported assurance report schema %q", report.SchemaVersion)
	}
	if strings.TrimSpace(report.Release.Tag) == "" {
		return Report{}, errCatalog("assurance report is missing its release tag")
	}
	if !report.Verdict.Overall.Valid() {
		return Report{}, fmt.Errorf("assurance report has unsupported verdict %q", report.Verdict.Overall)
	}
	for _, check := range report.Checks {
		if !idPattern.MatchString(check.ID) {
			return Report{}, fmt.Errorf("assurance report has invalid check id %q", check.ID)
		}
		if !check.Status.Valid() {
			return Report{}, fmt.Errorf("check %q has unsupported status %q", check.ID, check.Status)
		}
	}
	return report, nil
}

// LoadReport reads and validates the report at path.
func LoadReport(path string) (Report, error) {
	data, err := readBounded(path, MaxReportBytes)
	if err != nil {
		return Report{}, err
	}
	return ParseReport(data)
}

// IndexEntry is one release listed in the assurance index.
type IndexEntry struct {
	Tag         string `json:"tag"`
	Version     string `json:"version"`
	PublishedAt string `json:"published_at,omitempty"`
	GeneratedAt string `json:"generated_at"`
	Verdict     Status `json:"verdict"`
	Gates       int    `json:"gates_failed"`
	Path        string `json:"path"`
}

// Index lists every release that has a published assurance report, newest first.
type Index struct {
	SchemaVersion string       `json:"schema_version"`
	Latest        string       `json:"latest"`
	GeneratedAt   string       `json:"generated_at"`
	Releases      []IndexEntry `json:"releases"`
}

// Encode renders the index as indented JSON with a trailing newline.
func (i Index) Encode() ([]byte, error) {
	data, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode assurance index: %w", err)
	}
	return append(data, '\n'), nil
}

// ParseIndex decodes and validates an index document.
func ParseIndex(data []byte) (Index, error) {
	if len(data) > MaxReportBytes {
		return Index{}, fmt.Errorf("assurance index is %d bytes, limit is %d", len(data), MaxReportBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var index Index
	if err := decoder.Decode(&index); err != nil {
		return Index{}, fmt.Errorf("decode assurance index: %w", err)
	}
	if err := ensureEOF(decoder, "assurance index"); err != nil {
		return Index{}, err
	}
	if index.SchemaVersion != IndexSchema {
		return Index{}, fmt.Errorf("unsupported assurance index schema %q", index.SchemaVersion)
	}
	return index, nil
}
