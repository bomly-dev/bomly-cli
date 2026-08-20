package assurance

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// BenchmarkRunSchema is the schema of the performance sample manifest produced
// by internal/assurance/perfrun.
const BenchmarkRunSchema = "bomly.benchmark-run/v1"

// SBOMAssuranceSchema is the schema of the SBOM interoperability run manifest
// produced by internal/assurance/sbominterop.
const SBOMAssuranceSchema = "bomly.sbom-assurance-run/v1"

// maxManifestBytes bounds a converted manifest document.
const maxManifestBytes = 32 << 20

type benchmarkManifest struct {
	SchemaVersion string `json:"schema_version"`
	Case          struct {
		Name           string `json:"name"`
		SamplesPerMode int    `json:"samples_per_mode"`
		NetworkState   string `json:"network_state"`
	} `json:"case"`
	Summaries []struct {
		Mode                 string     `json:"mode"`
		Samples              int        `json:"samples"`
		MedianMS             float64    `json:"median_ms"`
		MeanMS               float64    `json:"mean_ms"`
		ConfidenceInterval95 [2]float64 `json:"confidence_interval_95_ms"`
		PeakMemoryBytes      uint64     `json:"peak_memory_bytes"`
	} `json:"summaries"`
	Gates struct {
		Passed                 bool   `json:"passed"`
		AllExitCodesZero       bool   `json:"all_exit_codes_zero"`
		NormalizedOutputStable bool   `json:"normalized_output_stable"`
		OutputCapPassed        bool   `json:"output_cap_passed"`
		FailureReason          string `json:"failure_reason"`
	} `json:"gates"`
}

// ConvertBenchmarkRun turns a performance sample manifest into a check result.
func ConvertBenchmarkRun(data []byte, base CheckResult) (CheckResult, error) {
	var manifest benchmarkManifest
	if err := decodeManifest(data, &manifest, "performance manifest"); err != nil {
		return CheckResult{}, err
	}
	if manifest.SchemaVersion != BenchmarkRunSchema {
		return CheckResult{}, fmt.Errorf("unsupported performance manifest schema %q", manifest.SchemaVersion)
	}
	result := base
	result.SchemaVersion = CheckSchema
	result.Status = StatusPass
	if !manifest.Gates.Passed {
		result.Status = StatusFail
	}
	result.Metrics = map[string]float64{"samples_per_mode": float64(manifest.Case.SamplesPerMode)}
	var peak float64
	for _, summary := range manifest.Summaries {
		mode := strings.ToLower(summary.Mode)
		result.Metrics[mode+"_median_ms"] = round(summary.MedianMS)
		result.Metrics[mode+"_mean_ms"] = round(summary.MeanMS)
		result.Metrics[mode+"_ci95_upper_ms"] = round(summary.ConfidenceInterval95[1])
		if float64(summary.PeakMemoryBytes) > peak {
			peak = float64(summary.PeakMemoryBytes)
		}
		result.Details = append(result.Details, Detail{
			Name:   mode + " cache",
			Status: StatusPass,
			Note: fmt.Sprintf("%d samples, median %.0f ms, mean %.0f ms",
				summary.Samples, summary.MedianMS, summary.MeanMS),
			DurationMS: round(summary.MedianMS),
		})
	}
	if peak > 0 {
		result.Metrics["peak_memory_bytes"] = peak
	}
	switch {
	case manifest.Gates.FailureReason != "":
		result.Summary = fmt.Sprintf("Performance sampling for %s failed: %s.",
			manifest.Case.Name, manifest.Gates.FailureReason)
	case len(manifest.Summaries) == 0:
		result.Status = StatusFail
		result.Summary = "The performance run recorded no samples."
	default:
		result.Summary = fmt.Sprintf("%s completed %d samples per cache mode with identical normalized output (%s).",
			manifest.Case.Name, manifest.Case.SamplesPerMode, describeModes(result.Metrics))
	}
	return result, nil
}

func describeModes(metrics map[string]float64) string {
	var parts []string
	for _, mode := range []string{"cold", "warm"} {
		if value, ok := metrics[mode+"_median_ms"]; ok {
			parts = append(parts, fmt.Sprintf("%s median %.0f ms", mode, value))
		}
	}
	if len(parts) == 0 {
		return "no timings recorded"
	}
	return strings.Join(parts, ", ")
}

type sbomAssuranceManifest struct {
	SchemaVersion string `json:"schema_version"`
	Validators    []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		SHA256  string `json:"sha256"`
	} `json:"validators"`
	Artifacts []struct {
		Format string `json:"format"`
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	} `json:"artifacts"`
	Commands []struct {
		Executable string   `json:"executable"`
		Args       []string `json:"args"`
		ExitCode   int      `json:"exit_code"`
		DurationMS int64    `json:"duration_ms"`
	} `json:"commands"`
	Failure string `json:"failure,omitempty"`
}

// ConvertSBOMAssurance turns an SBOM interoperability run manifest into a
// check result.
func ConvertSBOMAssurance(data []byte, base CheckResult) (CheckResult, error) {
	var manifest sbomAssuranceManifest
	if err := decodeManifest(data, &manifest, "SBOM assurance manifest"); err != nil {
		return CheckResult{}, err
	}
	if manifest.SchemaVersion != SBOMAssuranceSchema {
		return CheckResult{}, fmt.Errorf("unsupported SBOM assurance manifest schema %q", manifest.SchemaVersion)
	}
	result := base
	result.SchemaVersion = CheckSchema
	result.Status = StatusPass
	failures := 0
	for _, command := range manifest.Commands {
		status := StatusPass
		if command.ExitCode != 0 {
			status = StatusFail
			failures++
		}
		result.Details = append(result.Details, Detail{
			Name:       strings.TrimSpace(filepath.Base(command.Executable) + " " + firstArgument(command.Args)),
			Status:     status,
			Note:       fmt.Sprintf("exit code %d", command.ExitCode),
			DurationMS: float64(command.DurationMS),
		})
	}
	for _, validator := range manifest.Validators {
		result.Details = append(result.Details, Detail{
			Name:   validator.Name + " " + validator.Version,
			Status: StatusPass,
			Note:   "checksum " + shortHash(validator.SHA256),
		})
	}
	for _, artifact := range manifest.Artifacts {
		result.Artifacts = append(result.Artifacts, Artifact{
			Name: artifact.Format, SHA256: artifact.SHA256, Bytes: artifact.Bytes,
		})
	}
	result.Metrics = map[string]float64{
		"validators": float64(len(manifest.Validators)),
		"documents":  float64(len(manifest.Artifacts)),
	}
	switch {
	case manifest.Failure != "":
		result.Status = StatusFail
		result.Summary = "SBOM interoperability run failed: " + manifest.Failure + "."
	case failures > 0:
		result.Status = StatusFail
		result.Summary = fmt.Sprintf("%d of %d validator commands failed.", failures, len(manifest.Commands))
	case len(manifest.Artifacts) == 0:
		result.Status = StatusFail
		result.Summary = "The run produced no SBOM documents to validate."
	default:
		names := make([]string, 0, len(manifest.Validators))
		for _, validator := range manifest.Validators {
			names = append(names, validator.Name+" "+validator.Version)
		}
		result.Summary = fmt.Sprintf("%d generated SBOM documents passed %s.",
			len(manifest.Artifacts), strings.Join(names, " and "))
	}
	return result, nil
}

func firstArgument(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}

func round(value float64) float64 {
	return float64(int64(value*100+0.5)) / 100
}

func decodeManifest(data []byte, target any, what string) error {
	if len(data) > maxManifestBytes {
		return fmt.Errorf("%s is %d bytes, limit is %d", what, len(data), maxManifestBytes)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode %s: %w", what, err)
	}
	return nil
}
