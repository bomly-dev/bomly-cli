// Command benchmarkrun repeatedly executes one deterministic assurance case
// and records cold/warm samples in a versioned machine-readable manifest.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	runSchemaVersion   = "bomly.benchmark-run/v1"
	normalizationV1    = "bomly.benchmark-normalization/v1"
	defaultSamples     = 5
	defaultOutput      = ".benchmark-runs/performance"
	defaultNetworkMode = "unknown"
)

type runManifest struct {
	SchemaVersion        string        `json:"schema_version"`
	NormalizationVersion string        `json:"normalization_version"`
	GeneratedAt          string        `json:"generated_at"`
	Source               sourceInfo    `json:"source"`
	Tool                 toolInfo      `json:"tool"`
	Host                 hostInfo      `json:"host"`
	Case                 caseInfo      `json:"case"`
	Samples              []sample      `json:"samples"`
	Summaries            []modeSummary `json:"summaries"`
	Gates                gateSummary   `json:"gates"`
}

type sourceInfo struct {
	Revision string `json:"revision"`
	Dirty    bool   `json:"dirty"`
}

type toolInfo struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
	SHA256  string `json:"sha256"`
}

type hostInfo struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Go       string `json:"go_version"`
	CPUs     int    `json:"cpus"`
	Hostname string `json:"hostname,omitempty"`
}

type caseInfo struct {
	Name           string   `json:"name"`
	Command        string   `json:"command"`
	Args           []string `json:"args"`
	WorkingDir     string   `json:"working_directory"`
	SamplesPerMode int      `json:"samples_per_mode"`
	NetworkState   string   `json:"network_state"`
	CacheModes     []string `json:"cache_modes"`
}

type sample struct {
	Mode             string             `json:"mode"`
	Index            int                `json:"index"`
	StartedAt        string             `json:"started_at"`
	FinishedAt       string             `json:"finished_at"`
	ExitCode         int                `json:"exit_code"`
	StageTimingsMS   map[string]float64 `json:"stage_timings_ms"`
	PeakMemoryBytes  uint64             `json:"peak_memory_bytes,omitempty"`
	StdoutBytes      int                `json:"stdout_bytes"`
	StderrBytes      int                `json:"stderr_bytes"`
	StdoutSHA256     string             `json:"stdout_sha256"`
	NormalizedSHA256 string             `json:"normalized_stdout_sha256"`
	StderrSHA256     string             `json:"stderr_sha256"`
	CacheDirectory   string             `json:"cache_directory"`
	StdoutPath       string             `json:"stdout_path"`
	StderrPath       string             `json:"stderr_path"`
}

type modeSummary struct {
	Mode                 string     `json:"mode"`
	Samples              int        `json:"samples"`
	MedianMS             float64    `json:"median_ms"`
	MeanMS               float64    `json:"mean_ms"`
	StandardDeviationMS  float64    `json:"standard_deviation_ms"`
	MedianAbsoluteDevMS  float64    `json:"median_absolute_deviation_ms"`
	ConfidenceInterval95 [2]float64 `json:"confidence_interval_95_ms"`
	PeakMemoryBytes      uint64     `json:"peak_memory_bytes"`
	MedianOutputBytes    float64    `json:"median_output_bytes"`
}

type gateSummary struct {
	Passed                 bool   `json:"passed"`
	AllExitCodesZero       bool   `json:"all_exit_codes_zero"`
	NormalizedOutputStable bool   `json:"normalized_output_stable"`
	OutputCapBytes         int    `json:"output_cap_bytes,omitempty"`
	OutputCapPassed        bool   `json:"output_cap_passed"`
	FailureReason          string `json:"failure_reason,omitempty"`
}

func main() {
	var outputDir string
	var caseName string
	var samples int
	var networkState string
	var outputCap int
	flag.StringVar(&outputDir, "output", defaultOutput, "directory for raw samples and run-manifest.json")
	flag.StringVar(&caseName, "case", "benchmark-case", "stable case name")
	flag.IntVar(&samples, "samples", defaultSamples, "cold and warm sample count")
	flag.StringVar(&networkState, "network-state", defaultNetworkMode, "online, offline, or unknown")
	flag.IntVar(&outputCap, "max-output-bytes", 0, "optional stable stdout byte cap")
	flag.Parse()
	command := flag.Args()
	if len(command) == 0 {
		fmt.Fprintln(os.Stderr, "benchmarkrun requires a command after --")
		os.Exit(2)
	}
	if samples < 1 {
		fmt.Fprintln(os.Stderr, "samples must be positive")
		os.Exit(2)
	}
	switch networkState {
	case "online", "offline", "unknown":
	default:
		fmt.Fprintln(os.Stderr, "network-state must be online, offline, or unknown")
		os.Exit(2)
	}
	if err := run(outputDir, caseName, samples, networkState, outputCap, command[0], command[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(outputDir, caseName string, sampleCount int, networkState string, outputCap int, executable string, args []string) error {
	absoluteOutput, err := filepath.Abs(outputDir)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}
	if err := os.MkdirAll(absoluteOutput, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve working directory: %w", err)
	}
	tool, err := inspectTool(executable)
	if err != nil {
		return err
	}
	revision, dirty := gitState()
	hostname, _ := os.Hostname()
	manifest := runManifest{
		SchemaVersion:        runSchemaVersion,
		NormalizationVersion: normalizationV1,
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		Source:               sourceInfo{Revision: revision, Dirty: dirty},
		Tool:                 tool,
		Host:                 hostInfo{OS: runtime.GOOS, Arch: runtime.GOARCH, Go: runtime.Version(), CPUs: runtime.NumCPU(), Hostname: hostname},
		Case: caseInfo{
			Name: caseName, Command: executable, Args: append([]string(nil), args...),
			WorkingDir: workingDir, SamplesPerMode: sampleCount, NetworkState: networkState,
			CacheModes: []string{"cold", "warm"},
		},
	}

	for _, mode := range []string{"cold", "warm"} {
		for index := 1; index <= sampleCount; index++ {
			cacheDir := filepath.Join(absoluteOutput, "cache", mode)
			if mode == "cold" {
				cacheDir = filepath.Join(absoluteOutput, "cache", fmt.Sprintf("cold-%02d", index))
			}
			if err := os.MkdirAll(cacheDir, 0o755); err != nil {
				return fmt.Errorf("create %s cache: %w", mode, err)
			}
			current, err := executeSample(absoluteOutput, mode, index, cacheDir, executable, args)
			if err != nil {
				manifest.Samples = append(manifest.Samples, current)
				manifest.Summaries = summarizeModes(manifest.Samples)
				manifest.Gates = evaluateGates(manifest.Samples, outputCap)
				_ = writeManifest(absoluteOutput, manifest)
				return err
			}
			manifest.Samples = append(manifest.Samples, current)
		}
	}
	manifest.Summaries = summarizeModes(manifest.Samples)
	manifest.Gates = evaluateGates(manifest.Samples, outputCap)
	if err := writeManifest(absoluteOutput, manifest); err != nil {
		return err
	}
	if !manifest.Gates.Passed {
		return fmt.Errorf("benchmark invariant gate failed: %s", manifest.Gates.FailureReason)
	}
	return nil
}

func executeSample(outputDir, mode string, index int, cacheDir, executable string, args []string) (sample, error) {
	started := time.Now().UTC()
	command := exec.Command(executable, args...)
	command.Env = append(os.Environ(),
		"CI=1",
		"NO_COLOR=1",
		"BOMLY_NO_ANIMATION=1",
		"XDG_CACHE_HOME="+cacheDir,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	finished := time.Now().UTC()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}

	sampleDir := filepath.Join(outputDir, "samples")
	if mkdirErr := os.MkdirAll(sampleDir, 0o755); mkdirErr != nil {
		return sample{}, fmt.Errorf("create sample directory: %w", mkdirErr)
	}
	prefix := fmt.Sprintf("%s-%02d", mode, index)
	stdoutPath := filepath.Join(sampleDir, prefix+".stdout")
	stderrPath := filepath.Join(sampleDir, prefix+".stderr")
	if writeErr := os.WriteFile(stdoutPath, stdout.Bytes(), 0o600); writeErr != nil {
		return sample{}, fmt.Errorf("write sample stdout: %w", writeErr)
	}
	if writeErr := os.WriteFile(stderrPath, stderr.Bytes(), 0o600); writeErr != nil {
		return sample{}, fmt.Errorf("write sample stderr: %w", writeErr)
	}
	elapsedMS := float64(finished.Sub(started).Microseconds()) / 1000
	current := sample{
		Mode: mode, Index: index,
		StartedAt: started.Format(time.RFC3339Nano), FinishedAt: finished.Format(time.RFC3339Nano),
		ExitCode: exitCode, StageTimingsMS: map[string]float64{"command": elapsedMS},
		PeakMemoryBytes: peakMemoryBytes(command.ProcessState),
		StdoutBytes:     len(stdout.Bytes()), StderrBytes: len(stderr.Bytes()),
		StdoutSHA256: hashBytes(stdout.Bytes()), NormalizedSHA256: hashBytes(normalizeOutput(stdout.Bytes())),
		StderrSHA256:   hashBytes(stderr.Bytes()),
		CacheDirectory: cacheDir,
		StdoutPath:     filepath.ToSlash(stdoutPath), StderrPath: filepath.ToSlash(stderrPath),
	}
	if err != nil {
		return current, fmt.Errorf("%s sample %d exited %d: %w", mode, index, exitCode, err)
	}
	return current, nil
}

func normalizeOutput(data []byte) []byte {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return data
	}
	removeVolatile(value)
	normalized, err := json.Marshal(value)
	if err != nil {
		return data
	}
	return normalized
}

func removeVolatile(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range []string{"generated_at", "timestamp", "started_at", "finished_at", "duration_ms"} {
			delete(typed, key)
		}
		for _, child := range typed {
			removeVolatile(child)
		}
	case []any:
		for _, child := range typed {
			removeVolatile(child)
		}
	}
}

func summarizeModes(samples []sample) []modeSummary {
	var summaries []modeSummary
	for _, mode := range []string{"cold", "warm"} {
		var durations []float64
		var outputSizes []float64
		var peak uint64
		for _, current := range samples {
			if current.Mode != mode {
				continue
			}
			durations = append(durations, current.StageTimingsMS["command"])
			outputSizes = append(outputSizes, float64(current.StdoutBytes))
			if current.PeakMemoryBytes > peak {
				peak = current.PeakMemoryBytes
			}
		}
		if len(durations) == 0 {
			continue
		}
		mean, deviation := meanAndDeviation(durations)
		margin := 1.96 * deviation / math.Sqrt(float64(len(durations)))
		summaries = append(summaries, modeSummary{
			Mode: mode, Samples: len(durations),
			MedianMS: median(durations), MeanMS: mean, StandardDeviationMS: deviation,
			MedianAbsoluteDevMS:  medianAbsoluteDeviation(durations),
			ConfidenceInterval95: [2]float64{math.Max(0, mean-margin), mean + margin},
			PeakMemoryBytes:      peak, MedianOutputBytes: median(outputSizes),
		})
	}
	return summaries
}

func evaluateGates(samples []sample, outputCap int) gateSummary {
	gate := gateSummary{Passed: true, AllExitCodesZero: true, NormalizedOutputStable: true, OutputCapBytes: outputCap, OutputCapPassed: true}
	hashes := map[string]map[string]struct{}{"cold": {}, "warm": {}}
	for _, current := range samples {
		if current.ExitCode != 0 {
			gate.AllExitCodesZero = false
		}
		hashes[current.Mode][current.NormalizedSHA256] = struct{}{}
		if outputCap > 0 && current.StdoutBytes > outputCap {
			gate.OutputCapPassed = false
		}
	}
	for _, values := range hashes {
		if len(values) > 1 {
			gate.NormalizedOutputStable = false
		}
	}
	var failures []string
	if !gate.AllExitCodesZero {
		failures = append(failures, "non-zero exit code")
	}
	if !gate.NormalizedOutputStable {
		failures = append(failures, "normalized output changed within a cache mode")
	}
	if !gate.OutputCapPassed {
		failures = append(failures, "stdout exceeded configured cap")
	}
	gate.Passed = len(failures) == 0
	gate.FailureReason = strings.Join(failures, "; ")
	return gate
}

func inspectTool(path string) (toolInfo, error) {
	resolved, err := exec.LookPath(path)
	if err != nil {
		return toolInfo{}, fmt.Errorf("resolve benchmark command: %w", err)
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return toolInfo{}, fmt.Errorf("read benchmark command: %w", err)
	}
	versionCommand := exec.Command(resolved, "version")
	versionCommand.Env = append(os.Environ(), "CI=1", "NO_COLOR=1", "BOMLY_NO_ANIMATION=1")
	versionOutput, _ := versionCommand.CombinedOutput()
	return toolInfo{Path: resolved, Version: strings.TrimSpace(string(versionOutput)), SHA256: hashBytes(data)}, nil
}

func gitState() (string, bool) {
	revisionBytes, revisionErr := exec.Command("git", "rev-parse", "HEAD").Output()
	statusBytes, statusErr := exec.Command("git", "status", "--porcelain").Output()
	if revisionErr != nil || statusErr != nil {
		return "", false
	}
	return strings.TrimSpace(string(revisionBytes)), len(bytes.TrimSpace(statusBytes)) > 0
}

func peakMemoryBytes(state *os.ProcessState) uint64 {
	if state == nil {
		return 0
	}
	value := reflect.ValueOf(state.SysUsage())
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	field := value.FieldByName("Maxrss")
	if !field.IsValid() {
		return 0
	}
	var rss uint64
	switch field.Kind() {
	case reflect.Int, reflect.Int32, reflect.Int64:
		if field.Int() > 0 {
			rss = uint64(field.Int())
		}
	case reflect.Uint, reflect.Uint32, reflect.Uint64:
		rss = field.Uint()
	}
	if runtime.GOOS != "darwin" {
		rss *= 1024
	}
	return rss
}

func meanAndDeviation(values []float64) (float64, float64) {
	var total float64
	for _, value := range values {
		total += value
	}
	mean := total / float64(len(values))
	if len(values) < 2 {
		return mean, 0
	}
	var squared float64
	for _, value := range values {
		delta := value - mean
		squared += delta * delta
	}
	return mean, math.Sqrt(squared / float64(len(values)-1))
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}

func medianAbsoluteDeviation(values []float64) float64 {
	center := median(values)
	deviations := make([]float64, len(values))
	for index, value := range values {
		deviations[index] = math.Abs(value - center)
	}
	return median(deviations)
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeManifest(outputDir string, manifest runManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode benchmark run manifest: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(outputDir, "run-manifest.json"), data, 0o600); err != nil {
		return fmt.Errorf("write benchmark run manifest: %w", err)
	}
	return nil
}
