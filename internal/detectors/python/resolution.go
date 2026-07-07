package python

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

var sensitiveCommandFlags = map[string]struct{}{
	"--password":      {},
	"--token":         {},
	"--access-token":  {},
	"--client-secret": {},
	"--secret":        {},
	"--key":           {},
}

func manifestWithResolution(req sdk.DetectionRequest, patterns []string, resolution *sdk.ResolutionMetadata) sdk.ManifestMetadata {
	manifest := detectors.InferManifestMetadata(req, patterns)
	manifest.Resolution = resolution
	return manifest
}

func resolutionMetadata(method sdk.ResolutionMethod, installCommand []string, workingDir string, validation *sdk.ResolutionValidation) *sdk.ResolutionMetadata {
	out := &sdk.ResolutionMetadata{
		Method:          method,
		InstallExecuted: len(installCommand) > 0,
		Validation:      validation,
	}
	if len(installCommand) > 0 {
		out.InstallCommand = sanitizeCommand(installCommand)
		out.InstallWorkingDir = workingDir
	}
	return out
}

func sanitizeCommand(command []string) []string {
	out := make([]string, len(command))
	redactNext := false
	for i, value := range command {
		if redactNext {
			out[i] = "[REDACTED]"
			redactNext = false
			continue
		}
		if flag, valuePart, ok := strings.Cut(value, "="); ok {
			if _, sensitive := sensitiveCommandFlags[flag]; sensitive {
				out[i] = flag + "=[REDACTED]"
				continue
			}
			out[i] = flag + "=" + redactURL(valuePart)
			continue
		}
		if _, sensitive := sensitiveCommandFlags[value]; sensitive {
			out[i] = value
			redactNext = true
			continue
		}
		out[i] = redactURL(value)
	}
	return out
}

func redactURL(value string) string {
	if !strings.Contains(value, "://") {
		return value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User == nil {
		return value
	}
	parsed.User = url.User("[REDACTED]")
	return parsed.String()
}

func validateResolvedGraph(depsGraph *sdk.Graph, workingDir string, scope sdk.Scope) *sdk.ResolutionValidation {
	declared := declaredPythonDependenciesForValidation(workingDir, scope)
	if len(declared) == 0 {
		return &sdk.ResolutionValidation{Performed: false, Matched: true}
	}
	present := make(map[string]struct{}, depsGraph.Size())
	for _, pkg := range depsGraph.Nodes() {
		if pkg == nil || normalizePythonName(pkg.Name) == "root" {
			continue
		}
		present[normalizePythonName(pkg.Name)] = struct{}{}
	}
	missing := make([]string, 0)
	matched := 0
	for name := range declared {
		if _, ok := present[name]; ok {
			matched++
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	return &sdk.ResolutionValidation{
		Performed:     true,
		Matched:       len(missing) == 0,
		DeclaredCount: len(declared),
		MatchedCount:  matched,
		Missing:       missing,
	}
}

func requireValidResolvedGraph(detectorName string, depsGraph *sdk.Graph, workingDir string, scope sdk.Scope) (*sdk.ResolutionValidation, error) {
	validation := validateResolvedGraph(depsGraph, workingDir, scope)
	if validation.Performed && !validation.Matched {
		return validation, fmt.Errorf("%s: inspected Python environment does not match declared project dependencies (matched %d of %d; missing: %s)", detectorName, validation.MatchedCount, validation.DeclaredCount, strings.Join(validation.Missing, ", "))
	}
	return validation, nil
}

func logResolution(logger *zap.Logger, detectorName string, workingDir string, resolution *sdk.ResolutionMetadata) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if resolution == nil {
		return
	}
	fields := []zap.Field{
		zap.String("detector", detectorName),
		zap.String("working_dir", workingDir),
		zap.String("method", string(resolution.Method)),
		zap.Bool("install_executed", resolution.InstallExecuted),
	}
	if len(resolution.InstallCommand) > 0 {
		fields = append(fields, zap.Strings("install_command", resolution.InstallCommand))
	}
	if resolution.Validation != nil {
		fields = append(fields,
			zap.Bool("validation_performed", resolution.Validation.Performed),
			zap.Bool("validation_matched", resolution.Validation.Matched),
			zap.Int("declared_count", resolution.Validation.DeclaredCount),
			zap.Int("matched_count", resolution.Validation.MatchedCount),
		)
	}
	logger.Info(fmt.Sprintf("%s resolved dependencies using %s", detectorName, resolution.Method), fields...)
	if resolution.Validation != nil && len(resolution.Validation.Missing) > 0 {
		logger.Debug("python dependency validation missing declared packages", zap.String("detector", detectorName), zap.Strings("missing", resolution.Validation.Missing))
	}
}

func declaredPythonDependenciesForValidation(projectPath string, scope sdk.Scope) map[string]struct{} {
	declared := make(map[string]struct{})
	if projectPath == "" {
		return declared
	}
	collectRequirementValidationFiles(projectPath, scope, declared)
	collectPipfileValidationDependencies(filepath.Join(projectPath, "Pipfile"), scope, declared)
	collectPipfileLockValidationDependencies(filepath.Join(projectPath, "Pipfile.lock"), scope, declared)
	collectPyprojectValidationDependencies(filepath.Join(projectPath, "pyproject.toml"), scope, declared)
	return declared
}

func collectRequirementValidationFiles(projectPath string, scope sdk.Scope, declared map[string]struct{}) {
	seen := make(map[string]struct{})
	addPath := func(name string, depScope sdk.Scope) {
		if scope == sdk.ScopeRuntime && depScope == sdk.ScopeDevelopment {
			return
		}
		path := filepath.Join(projectPath, name)
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		collectRequirementValidationDependencies(path, declared)
	}
	for _, name := range []string{"requirements.txt", "requirements.in", "requirements.lock"} {
		addPath(name, sdk.ScopeRuntime)
	}
	addPath("requirements-dev.txt", sdk.ScopeDevelopment)
	matches, _ := filepath.Glob(filepath.Join(projectPath, "*requirements*.txt"))
	for _, path := range matches {
		name := filepath.Base(path)
		depScope := sdk.ScopeRuntime
		if strings.Contains(strings.ToLower(name), "dev") {
			depScope = sdk.ScopeDevelopment
		}
		addPath(name, depScope)
	}
}

func collectRequirementValidationDependencies(path string, declared map[string]struct{}) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		addDeclaredPythonName(requirementName(line), declared)
	}
}

func collectPipfileValidationDependencies(path string, scope sdk.Scope, declared map[string]struct{}) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	sectionScope := sdk.ScopeUnknown
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		switch strings.ToLower(line) {
		case "[packages]":
			sectionScope = sdk.ScopeRuntime
			continue
		case "[dev-packages]":
			sectionScope = sdk.ScopeDevelopment
			continue
		}
		if strings.HasPrefix(line, "[") {
			sectionScope = sdk.ScopeUnknown
			continue
		}
		if sectionScope == sdk.ScopeUnknown || (scope == sdk.ScopeRuntime && sectionScope == sdk.ScopeDevelopment) {
			continue
		}
		if key, _, ok := strings.Cut(line, "="); ok {
			addDeclaredPythonName(strings.TrimSpace(key), declared)
		}
	}
}

func collectPipfileLockValidationDependencies(path string, scope sdk.Scope, declared map[string]struct{}) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var lock pipfileLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return
	}
	for name := range lock.Default {
		addDeclaredPythonName(name, declared)
	}
	if scope != sdk.ScopeRuntime {
		for name := range lock.Develop {
			addDeclaredPythonName(name, declared)
		}
	}
}

func collectPyprojectValidationDependencies(path string, scope sdk.Scope, declared map[string]struct{}) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	activeScope := sdk.ScopeUnknown
	inArray := false
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inArray = false
			activeScope = sdk.ScopeUnknown
			switch {
			case line == "[project]" || line == "[tool.poetry.dependencies]":
				activeScope = sdk.ScopeRuntime
			case strings.HasPrefix(line, "[tool.poetry.group.") && strings.HasSuffix(line, ".dependencies]"):
				activeScope = sdk.ScopeDevelopment
			}
			continue
		}
		if activeScope == sdk.ScopeUnknown || (scope == sdk.ScopeRuntime && activeScope == sdk.ScopeDevelopment) {
			continue
		}
		if strings.HasPrefix(line, "dependencies = [") {
			inArray = true
			line = strings.TrimPrefix(line, "dependencies = [")
		}
		if inArray {
			if strings.Contains(line, "]") {
				inArray = false
				line = strings.SplitN(line, "]", 2)[0]
			}
			for _, part := range strings.Split(line, ",") {
				addDeclaredPythonName(requirementName(strings.Trim(part, ` "'`)), declared)
			}
			continue
		}
		if key, _, ok := strings.Cut(line, "="); ok && activeScope != sdk.ScopeUnknown {
			name := strings.TrimSpace(key)
			if name != "python" {
				addDeclaredPythonName(name, declared)
			}
		}
	}
}
