// Command assurance drives Bomly's release assurance framework. Quality checks
// call it to emit their results, and the release pipeline calls it to judge a
// stage and to build the per-release report the public assurance page renders.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/assurance"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "emit":
		err = runEmit(os.Args[2:])
	case "gotest":
		err = runGoTest(os.Args[2:])
	case "convert":
		err = runConvert(os.Args[2:])
	case "verify-release":
		err = runVerifyRelease(os.Args[2:])
	case "verdict":
		err = runVerdict(os.Args[2:])
	case "report":
		err = runReport(os.Args[2:])
	case "catalog-validate":
		err = runCatalogValidate(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "assurance: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		var blocking blockingError
		if errors.As(err, &blocking) {
			fmt.Fprintln(os.Stderr, "assurance:", blocking.Error())
			os.Exit(blocking.code)
		}
		fmt.Fprintln(os.Stderr, "assurance:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `assurance drives Bomly's release assurance framework.

Commands:
  emit              write a check result from flags
  gotest            turn a "go test -json" stream into a check result
  convert           turn a tool manifest into a check result
  verify-release    verify downloaded release assets and emit check results
  verdict           judge one stage from collected check results
  report            build the per-release assurance report and index
  catalog-validate  validate the assurance catalog and print its contents

Run "assurance <command> -h" for the flags of one command.
`)
}

type blockingError struct {
	message string
	code    int
}

func (e blockingError) Error() string { return e.message }

// ---------------------------------------------------------------- shared ---

type resultContext struct {
	catalog     *assurance.Catalog
	catalogPath string
	root        string
}

// loadContext resolves the catalog a result is described by. A catalog that
// cannot be read at all leaves the context empty, so a check running outside a
// checkout can still emit with an explicit --stage and --level; a catalog that
// exists but does not parse is reported, because silently treating every check
// as undeclared would drop the stage and level a gate depends on.
func loadContext(catalogPath string) (resultContext, error) {
	ctx := resultContext{catalogPath: catalogPath}
	root, err := repositoryRoot()
	if err != nil {
		return ctx, nil
	}
	ctx.root = root
	path := catalogPath
	if path == "" {
		path = filepath.Join(root, filepath.FromSlash(assurance.DefaultCatalogPath))
		if _, statErr := os.Stat(path); statErr != nil {
			return ctx, nil
		}
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(root, filepath.FromSlash(path))
	}
	catalog, err := assurance.LoadCatalog(path)
	if err != nil {
		return ctx, err
	}
	ctx.catalog = &catalog
	ctx.catalogPath = path
	return ctx, nil
}

func mustLoadCatalog(catalogPath string) (assurance.Catalog, string, error) {
	ctx, err := loadContext(catalogPath)
	if err != nil {
		return assurance.Catalog{}, "", err
	}
	if ctx.catalog == nil {
		path := catalogPath
		if path == "" {
			path = assurance.DefaultCatalogPath
		}
		resolved := path
		if ctx.root != "" && !filepath.IsAbs(path) {
			resolved = filepath.Join(ctx.root, filepath.FromSlash(path))
		}
		catalog, err := assurance.LoadCatalog(resolved)
		if err != nil {
			return assurance.Catalog{}, "", err
		}
		return catalog, resolved, nil
	}
	return *ctx.catalog, ctx.catalogPath, nil
}

// catalogRoot resolves the repository a catalog's paths are relative to. An
// explicit root lets the tool run from one checkout against another, which is
// how the goldens workflow refreshes checksums without executing code from the
// branch it is refreshing.
func catalogRoot(explicit string) (string, error) {
	if explicit == "" {
		return repositoryRoot()
	}
	absolute, err := filepath.Abs(explicit)
	if err != nil {
		return "", fmt.Errorf("resolve --root: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve --root: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("--root %q is not a directory", explicit)
	}
	return absolute, nil
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

// baseResult fills the fields every check result shares from the environment.
func baseResult(id, instance string) assurance.CheckResult {
	result := assurance.CheckResult{
		SchemaVersion: assurance.CheckSchema,
		ID:            id,
		Instance:      instance,
		Ref:           os.Getenv("GITHUB_REF"),
		Commit:        os.Getenv("GITHUB_SHA"),
		Tag:           os.Getenv("BOMLY_ASSURANCE_TAG"),
		Job:           os.Getenv("GITHUB_JOB"),
		Runner:        assurance.Runner{OS: goos(), Arch: goarch(), GoVersion: goVersion()},
		StartedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	result.Version = strings.TrimPrefix(result.Tag, "v")
	result.RunURL = jobURL(runURL())
	return result
}

func runURL() string {
	server := os.Getenv("GITHUB_SERVER_URL")
	repository := os.Getenv("GITHUB_REPOSITORY")
	runID := os.Getenv("GITHUB_RUN_ID")
	if server == "" || repository == "" || runID == "" {
		return ""
	}
	url := fmt.Sprintf("%s/%s/actions/runs/%s", server, repository, runID)
	if attempt := os.Getenv("GITHUB_RUN_ATTEMPT"); attempt != "" {
		url += "/attempts/" + attempt
	}
	return url
}

// applyCatalog fills the stage and level a check is declared with.
func applyCatalog(result *assurance.CheckResult, catalog *assurance.Catalog, stage, level string) error {
	if catalog != nil {
		if check, found := catalog.Check(result.ID); found {
			if result.Stage == "" {
				result.Stage = check.Stage
			}
			if result.Level == "" {
				result.Level = check.Level
			}
		}
	}
	if stage != "" {
		result.Stage = assurance.Stage(stage)
	}
	if level != "" {
		result.Level = assurance.Level(level)
	}
	if result.Stage == "" {
		return fmt.Errorf("check %q is not in the catalog, so --stage is required", result.ID)
	}
	return nil
}

func writeResult(outDir string, result assurance.CheckResult, stepSummary bool, reproduce [][]string) error {
	if err := result.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create result directory: %w", err)
	}
	data, err := result.Encode()
	if err != nil {
		return err
	}
	path := filepath.Join(outDir, result.FileName())
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("%s %s: %s\n", assurance.StatusIcon(result.Status), result.Key(), result.Summary)
	if stepSummary {
		if err := appendStepSummary(assurance.RenderResultMarkdown(result, reproduce)); err != nil {
			return err
		}
	}
	return nil
}

func appendStepSummary(markdown string) error {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return nil
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open step summary: %w", err)
	}
	defer file.Close()
	if _, err := file.WriteString(markdown); err != nil {
		return fmt.Errorf("write step summary: %w", err)
	}
	return nil
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func splitPair(value, what string) (string, string, error) {
	key, rest, found := strings.Cut(value, "=")
	if !found || strings.TrimSpace(key) == "" {
		return "", "", fmt.Errorf("%s %q must be written as name=value", what, value)
	}
	return strings.TrimSpace(key), strings.TrimSpace(rest), nil
}

func statusFromExit(code int) assurance.Status {
	if code == 0 {
		return assurance.StatusPass
	}
	return assurance.StatusFail
}
